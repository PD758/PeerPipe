from __future__ import annotations

import asyncio
import orjson
import logging
import uuid
import ssl
import typing
import string
import secrets
import dataclasses
import websockets
from aiortc import RTCPeerConnection, RTCSessionDescription, \
    RTCDataChannel, RTCIceServer, RTCConfiguration, RTCIceCandidate
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp

import lz4.frame
import zstandard

import config
import net

if config.ENABLE_GOST_ENCRYPTION:
    import gostcrypto

logger = logging.getLogger(__name__)

ICE_SERVERS = [
    RTCIceServer(urls=url) for url in config.ICE_SERVERS_URLS
]
ICE_CONFIGURATION = RTCConfiguration(iceServers=ICE_SERVERS)

def uuid4():
    return str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
def check_uuid4(u: str):
    if len(u) != 36:
        return False
    try:
        return (str(uuid.UUID(u, version=4)) == u)
    except ValueError:
        return False

_ALLOWED_CHARS = frozenset(string.ascii_letters + string.digits + "_+-=/ $%#@!?,;()[]")
def _check(name: str|None) -> str|None:
    if name is None:
        return None
    if not (4 <= len(name) <= 48):
        return None
    if not all(c in _ALLOWED_CHARS for c in name):
        return None
    return name
check_roomname = _check
check_username = _check

class TaskManager:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    def __init__(self):
        if getattr(self, "initialized", False):
            return
        self.initialized: bool = True
        self.tasks: set[asyncio.Task] = set()
    def shutdown(self):
        for task in self.tasks:
            task.cancel()
    def add_task(self, task: asyncio.Task):
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

class ServerWSSClient:
    def __init__(self):
        self.websocket: typing.Optional[websockets.ClientConnection] = None
        self.is_alive = False
        self._e = None
    async def start(self):
        try:
            if config.DEBUG_SERVER_DISABLE_SSL:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                self.websocket = await websockets.connect(uri=config.SERVER_URI, compression="deflate", ssl=ssl_context)
            else:
                self.websocket = await websockets.connect(uri=config.SERVER_URI, compression="deflate")
            self.is_alive = True
            logger.info("WSS: подключён к серверу")
        except PermissionError:
            logger.info("WSS: не удалось подключиться к сервису")
        except ConnectionRefusedError:
            logger.info("WSS: не удалось подключиться к серверу: подключение отклонено")
        except TimeoutError:
            logger.info("WSS: не удалось подключиться к серверу: таймаут соединения")
        except Exception as e:
            logger.error("WSS: не удалось подключиться к серверу", exc_info=True)
    async def stop(self):
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
            self.is_alive = False
    async def send(self, data: bytes, as_text: bool|None = None) -> None:
        if self.websocket:
            try:
                await self.websocket.send(data, text=as_text)
                #logger.debug("WSS: sent %s", data)
            except websockets.ConnectionClosed as e:
                self._e = e
                await self.stop()
        else:
            raise RuntimeError("WSS: попытка отправить данные по закрытому сокету")
    async def recv(self, timeout: float = -1) -> bytes:
        if not self.websocket:
            raise RuntimeError("WSS: попытка получить данные с закрытого соединения")
        try:
            if timeout != -1:
                res = await asyncio.wait_for(self.websocket.recv(decode=False), timeout=timeout)
            else:
                res = await self.websocket.recv(decode=False)
            #logger.debug("WSS: got %s", res)
            return res
        except websockets.ConnectionClosed as e:
            self._e = e
            await self.stop()
            return b""
        except TimeoutError:
            return b""

@dataclasses.dataclass
class ConnectionConfig:
    Compression: typing.Literal["none", "lz4", "zstd", "zstd-hc"] = "none"
    ExtendedCompression: bool = False
    UnreliableChannels: bool = False
    SharedPorts: tuple[str, ...] = tuple()
    ShareIP: str = "127.0.1.1"

def make_body(type: str, data: dict[str, typing.Any] = {}):
    return {
        "type": type,
        **data
    }

class WebRTCInstance:
    def __init__(self, event_callback: typing.Callable[[WebRTCInstance], None], peer_name: str, self_name: str, negotiation_config: ConnectionConfig):
        self.name = self_name
        self.peer_name = peer_name
        self.config = negotiation_config
        self.event_queue: list = []
        self._event_callback = event_callback
        self.closed = False
        self._ctrl_initialized = False
        
        self.listen_servers: dict[str, asyncio.Server|net._UDPServer] = {} # "PORT:PROTO": Server
        self.outcoming_channels: dict[str, RTCDataChannel] = {} # "proxy-UUID": RTCDC
        self.ev_waiting: dict[str, asyncio.Future] = {}
        
        self.incoming_channels: dict[str, RTCDataChannel] = {}  # "proxy-UUID": RTCDC
        
        self._zcompressor: typing.Optional[zstandard.ZstdCompressor] = None
        self._zdecompressor: typing.Optional[zstandard.ZstdDecompressor] = None
        
        if config.ENABLE_GOST_ENCRYPTION:
            # contains both decrypt and encrypt threads for data transfer
            self._data_encp: dict[str, tuple[gostcrypto.gostcipher.gost_34_13_2015.GOST34132015ctr,
                                             gostcrypto.gostcipher.gost_34_13_2015.GOST34132015ctr]] = {}
            self._neg_key: str = ""
        
    
    async def begin(self):
        if hasattr(self, "conn"):
            raise RuntimeError("WebRTCI: уже начат!")
        self.conn = RTCPeerConnection(configuration=ICE_CONFIGURATION)
        self.conn.addTransceiver("audio", direction="recvonly")
        self.conn.on('datachannel', self._on_channel_open)
        self.conn.on("connectionstatechange", self._on_conn_state_change)
        self.conn.on("icecandidate", self._on_ice_update)
        
        if self.is_offerer():
            await self._offer_state()
    
    async def on_sdp(self, sdp_type, sdp_data):
        if self.closed:
            return
        if sdp_type == "offer":
            if self.is_offerer():
                logger.error("WebRTCI: got offer while offerer")
                return
            await self.conn.setRemoteDescription(RTCSessionDescription(sdp=sdp_data, type="offer"))
            answer = await self.conn.createAnswer()
            await self.conn.setLocalDescription(answer)
            self._queue(("send",
                         make_body("SDP_NEW_STATE", {
                             "target_user": self.peer_name,
                             "sdp_type": "answer",
                             "sdp_data": self.conn.localDescription.sdp
                         })))
        elif sdp_type == "answer":
            await self.conn.setRemoteDescription(RTCSessionDescription(sdp=sdp_data, type="answer"))
        elif sdp_type == "candidate":
            if not isinstance(sdp_data, dict):
                logger.debug("WebRTCI: invalid candidate description format")
                return
            candidate = sdp_data.get("candidate", None)
            sdpMid = sdp_data.get("sdpMid", None)
            sdpMLineIndex = sdp_data.get("sdpMLineIndex", None)
            if not isinstance(candidate, str) or not (isinstance(sdpMid, str) or sdpMid is None) or not\
               (isinstance(sdpMLineIndex, int) or sdpMLineIndex is None):
                logger.debug("WebRTCI: invalid candidate SDP format")
                return
            candidate = candidate_from_sdp(candidate)
            candidate.sdpMid = sdpMid
            candidate.sdpMLineIndex = sdpMLineIndex
            await self.conn.addIceCandidate(candidate)
    def _queue(self, msg):
        self.event_queue.append(msg)
        self._event_callback(self)
    def is_offerer(self) -> bool:
        return (self.name < self.peer_name)
    
    def _on_ice_update(self, candidate: RTCIceCandidate):
        if candidate:
            DATA = {
                "candidate": candidate_to_sdp(candidate),
                "sdpMid": candidate.sdpMid,
                "sdpMLineIndex": candidate.sdpMLineIndex
            }
            self._queue(
                ("send",
                 make_body("SDP_NEW_STATE", {
                         "target_user": self.peer_name,
                         "sdp_type": "candidate",
                         "sdp_data": DATA
                     }
                 ))
            )
    
    async def _offer_state(self):
        self._control_channel = self.conn.createDataChannel(config.CONTROL_CHANNEL_ID)
        
        @self._control_channel.on("open")
        def _initialize_opener():
            logger.debug("WebRTCI: initialize CTRL as offerer")
            TaskManager().add_task(
                asyncio.create_task(self._initialize())
            )
        
        @self._control_channel.on("message")
        def _ctrl_msg_opener(message):
            TaskManager().add_task(
                asyncio.create_task(self._ctrl_msg(message=message))
            )
        
        @self._control_channel.on("close")
        def _on_close():
            self.terminate()
        
        offer = await self.conn.createOffer()
        await self.conn.setLocalDescription(offer)
        self._queue(('send', make_body(
            "SDP_NEW_STATE",
            {
                "target_user": self.peer_name,
                "sdp_type": "offer",
                "sdp_data": self.conn.localDescription.sdp
            }
        )))
    
    def _on_channel_open(self, channel: RTCDataChannel):
        logger.debug("WebRTCI: opened channel %s", channel.label)
        if channel.label == config.CONTROL_CHANNEL_ID:
            self._control_channel = channel
            channel.on("message", self._ctrl_msg)
            TaskManager().add_task(
                asyncio.create_task(self._initialize())
            )
        elif channel.label.startswith(config.PROXY_CHANNEL_PREFIX):
            if channel.label in self.ev_waiting:
                self.outcoming_channels[channel.label] = channel
                self.ev_waiting[channel.label].set_result(0)
        else:
            channel.close()
            logger.error("WebRTC: got unknown channel %s created by %s", channel.label, self.peer_name)

    def _on_conn_state_change(self):
        if self.conn.connectionState in ('failed', 'closed'):
            self.closed = True
    
    def terminate(self, do_notify: bool = True):
        if hasattr(self, 'conn'):
            TaskManager().add_task(
                asyncio.create_task(self.conn.close())
            )
        for port, server in self.listen_servers.items():
            if isinstance(server, asyncio.Server):
                server.close_clients()
            server.close()
            self._queue(('stop_listen', port))
        if do_notify:
            self._queue(('exit',))
        self.closed = True
    
    def _generate_initialize(self):
        _r = {
            "type": "INIT",
            "IL_user": self.peer_name,
            "config": {
                "unreliable_channels": self.config.UnreliableChannels,
                "compression_type": self.config.Compression,
                "extended_compression": self.config.ExtendedCompression
            },
            "ports": list(self.config.SharedPorts)
        }
        if config.ENABLE_GOST_ENCRYPTION and self.is_offerer():
            self._neg_key = secrets.token_bytes(32).hex()
            _r["GOST_KEY_C"] = self._neg_key
        return _r
    async def _handle_initialize(self, message: dict):
        logger.debug("WebRTCI: initializing connection")
        COMPRESSIONS = ('none', 'lz4', 'zstd', 'zstd-hc')
        if self._ctrl_initialized:
            logger.debug("WebRTCI: connection with %s terminated, doubled INIT", self.peer_name)
            self.terminate()
            return
        IL_user = message.get('IL_user', None)
        cfg = message.get('config', {
            "unreliable_channels": False,
            "compression_type": 'none',
            "extended_compression": False
        })
        ports = message.get('ports', [])
        if not (IL_user==self.name and isinstance(cfg, dict) and
                isinstance(ports, list) and
                isinstance(cfg.get('unreliable_channels', False), bool) and
                cfg.get('compression_type', 'none') in COMPRESSIONS and
                isinstance(cfg.get('extended_compression', False), bool)):
            logger.debug('WebRTCI: invalid INIT message from %s: %s', self.peer_name, message)
            self.terminate()
            return
        if len(ports) > 50:
            logger.warning("WebRTCI: too much ports presented by peer: %d, limiting to first 50s", len(ports))
            ports = ports[:50]
        
        if config.ENABLE_GOST_ENCRYPTION and not self.is_offerer():
            self._neg_key = message.get("GOST_KEY_C", "")
            if not self._neg_key:
                logger.error("WebRTCI: failed to negotiate GOST encryption key")
        
        self.theirPorts: list[str] = ports
        self.config.Compression = COMPRESSIONS[min(COMPRESSIONS.index(self.config.Compression),
                                                   COMPRESSIONS.index(cfg.get('compression_type', 'none')))]
        self.config.ExtendedCompression = (self.config.ExtendedCompression and cfg.get('extended_compression', False)) and \
                                        self.config.Compression in ('zstd', 'zstd-hc')
        self.config.UnreliableChannels = (self.config.UnreliableChannels and cfg.get('unreliable_channels', False)) and\
            not self.config.ExtendedCompression
        
        if self.config.Compression == 'zstd':
            self._zcompressor = zstandard.ZstdCompressor(level=3)
            self._zdecompressor = zstandard.ZstdDecompressor()
        elif self.config.Compression == 'zstd-hc':
            self._zcompressor = zstandard.ZstdCompressor(level=15)
            self._zdecompressor = zstandard.ZstdDecompressor()
        
        logger.debug("WebRTCI: %s negotiation succeded: {%s,%s,%s}",
                     self.peer_name, self.config.UnreliableChannels,
                     self.config.Compression, self.config.ExtendedCompression)
        await self._set_up_listeners()
    
    async def _initialize(self):
        self._control_channel.send(orjson.dumps(self._generate_initialize()))
        
    async def _ctrl_msg(self, message: bytes):
        logger.debug("WebRTCI: got ctrl msg %s", message)
        
        try:
            data = orjson.loads(message)
        except orjson.JSONDecodeError:
            logger.debug("WebRTCI: failed decode CTRL of %s, terminating", self.peer_name)
            self.terminate()
            return
        if not isinstance(data, dict) or 'type' not in data:
            logger.debug('WebRTCI: invalid data message from %s, terminating', self.peer_name)
            self.terminate()
            return
        match data["type"]:
            case 'INIT':
                await self._handle_initialize(data)
            case 'BEGIN_PROXY':
                self._handle_proxify(data)
            case 'SUCCESS':
                self._handle_success(data)
            case 'FAILED':
                self._handle_failed(data)
            case _:
                logger.debug("Invalid message from %s: %s",
                             self.peer_name, data["type"])
        return
    
    def _search_port(self, proto: typing.Literal["TCP", "UDP"], prio: int = 0) -> int:
        ALLOWED_PORTS = frozenset(range(20_000, 60_000))
        if prio not in ALLOWED_PORTS:
            prio = 0
        
        check_free = (net.is_tcp_port_free if proto=="TCP" else net.is_udp_port_free)
        #ip = self.config.ShareIP
        if prio and check_free(prio):
            return prio
        for port in ALLOWED_PORTS:
            if check_free(port):
                return port
        raise RuntimeError("Cannot found free port")
        
    async def _set_up_listeners(self):
        logger.debug("WebRTCI: setting up listeners")
        
        def make_factory(port, protocol):
            return lambda r, w: self._on_listener_connect_cb(reader=r, writer=w, port_info=(port, protocol))
        
        for port_s in self.theirPorts:
            if not isinstance(port_s, str):
                logger.debug("WebRTCI: skipping port, invalid type")
                continue
            port_r = port_s.split(':')
            if (len(port_r) != 2) or port_r[1] not in ('TCP', 'UDP'):
                logger.debug("WebRTCI: skipping port, invalid format")
                continue
            port_d, protocol = port_r
            if protocol not in ('TCP', 'UDP'):
                logger.debug("WebRTCI: tried to setup invalid listener on proto %s", protocol)
                continue
            try:
                port_d = int(port_d)
            except ValueError:
                logger.debug("WebRTCI: failed port conversion, skipping")
                continue
            port_real = self._search_port(prio=port_d, proto=protocol)
            try:
                if protocol == "UDP":
                    self.listen_servers[port_s] = await net.start_udp_server(make_factory(int(port_d), "UDP"), host=self.config.ShareIP, port=port_real)
                else:
                    self.listen_servers[port_s] = await asyncio.start_server(make_factory(int(port_d), "TCP"), host=self.config.ShareIP, port=port_real)
            except OSError as e:
                if 'could not bind' in str(e) or 'error while attempting to bind' in str(e):
                    logger.critical("WebRTCI: не удалось прикрепить сокет к адресу в ОС. Похоже, что вы используете ОС семейства *NIX"
                                    "- для работы loopback адресов кроме 127.0.0.1 в них необходимо выполнить команду:\n"
                                    f"sudo ifconfig lo0 alias {self.config.ShareIP} up\n"
                                    "(вас могут попросить выполнить команду несколько раз для каждого члена комнаты. она выполняется один раз на всё время в системе для каждого IP)")
                    self._queue(('warn', '[e]Ошибка во время подключения участника. Проверьте вывод программы в консоли.'))
                    logger.debug('WebRTCI: error info: %s', e, exc_info=True)
                else:
                    logger.error("WebRTCI: unknown error while binding server", exc_info=True)
                return
            logger.debug("WebRTCI: set up listener at %s", (self.config.ShareIP, port_real))
            self._queue(('listen', (port_d, protocol), port_real))
    
    async def _do_pipe(self, chid: str, channel: RTCDataChannel, reader: asyncio.StreamReader|net._UDPStreamReader,
                       writer: asyncio.StreamWriter|net._UDPStreamWriter|net._UDPClientStreamWriter, offerer: bool,
                       protocol: typing.Literal["TCP", "UDP"]):
        logger.debug("WebRTCI: piping %s (%s)", chid, channel.readyState)
        if protocol == "TCP":
            if not isinstance(reader, asyncio.StreamReader) or not isinstance(writer, asyncio.StreamWriter):
                logger.critical("WebRTCI: invalid protocol handle: %s %s", type(reader), type(writer))
                return
            await self._do_pipe_tcp(chid, channel, reader, writer, offerer)
        else: # TODO fix: when two protocols present on same port, invalid protocol handler triggers
            if not isinstance(reader, net._UDPStreamReader) or not (isinstance(writer, net._UDPStreamWriter) or isinstance(writer, net._UDPClientStreamWriter)):
                logger.critical("WebRTCI: invalid protocol handle: %s %s", type(reader), type(writer))
                return
            await self._do_pipe_udp(chid, channel, reader, writer, offerer)
    async def _do_pipe_tcp(self, chid: str, channel: RTCDataChannel, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter, offerer: bool):
        logger.debug("WebRTCI: piping TCP for %s (%s)", chid, channel.readyState)

        # Маркеры для управления состоянием half-close
        #EOF_MARKER = b'\x01\x03'  # Специальная последовательность для EOF
        #START_MARKER = b'\x01\x02' # Твой существующий маркер старта

        local_eof = asyncio.Event()
        remote_eof = asyncio.Event()
        sigstart_ev = asyncio.Event()

        async def socket_reader():
            """Читает из локального сокета и отправляет в WebRTC."""
            try:
                first_recv = True
                while not local_eof.is_set():
                    data = await reader.read(16384)
                    
                    if offerer and first_recv:
                        first_recv = False
                        await sigstart_ev.wait()

                    if not data: # Локальный сокет прислал EOF (write_eof())
                        if channel.readyState == 'open':
                            channel.send(self._handle_raw_data(b'', chid, False, True))
                        break # Завершаем чтение

                    # Отправляем обычные данные
                    if channel.readyState == 'open':
                        channel.send(self._handle_raw_data(data, chid, False, False))

            except (ConnectionResetError, asyncio.CancelledError):
                pass # Соединение разорвано, просто выходим
            finally:
                # Сигнализируем, что наш локальный read-пайп завершен
                local_eof.set()

        async def socket_writer():
            """Получает данные из WebRTC и пишет в локальный сокет."""
            nonlocal sigstart_ev
            
            @channel.on("message")
            def on_message(message):
                nonlocal sigstart_ev
                
                is_sseq, is_eot, raw = self._handle_comps_data(message, chid)
                if offerer and is_sseq:
                    sigstart_ev.set()
                    return
                
                if is_eot:
                    if not writer.is_closing():
                        writer.write_eof()
                    remote_eof.set()
                    return 

                if not writer.is_closing():
                    try:
                        writer.write(raw)
                    except Exception as e:
                        logger.debug("WebRTCI: piper: %s during socket send", e)
                        # При ошибке записи считаем, что оба направления мертвы
                        local_eof.set()
                        remote_eof.set()
            
            # Если канал закрывается, это "жесткий" EOF в обе стороны
            @channel.on("close")
            def on_close():
                local_eof.set()
                remote_eof.set()

            if not offerer:
                channel.send(self._handle_raw_data(b'', chid, True, False))
            
            # Ждем, пока удаленная сторона не пришлет EOF
            await remote_eof.wait()


        tasks = (asyncio.create_task(socket_reader()), asyncio.create_task(socket_writer()))
        TaskManager().add_task(tasks[0])
        TaskManager().add_task(tasks[1])
        
        # Ждем, пока ОБА направления не будут закрыты (получен EOF с обеих сторон)
        await asyncio.gather(local_eof.wait(), remote_eof.wait())

        # Теперь можно безопасно все закрывать
        for task in tasks:
            task.cancel()
        if channel.readyState == 'open':
            channel.close()
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        self._after_close(chid)
        logger.debug("WebRTCI: TCP pipe closed for %s", chid)
    async def _do_pipe_udp(self, chid: str, channel: RTCDataChannel, reader: net._UDPStreamReader,
                           writer: net._UDPStreamWriter | net._UDPClientStreamWriter, offerer: bool):
        logger.debug("WebRTCI: piping UDP for %s (%s)", chid, channel.readyState)
        pipe_closed = asyncio.Event()
        sigstart_ev = asyncio.Event()

        # batching settings
        BATCH_TIMEOUT = 0.002  # 2ms
        BATCH_SIZE_LIMIT = 16000 # Чуть меньше 16KB

        async def socket_reader():
            """Читает датаграммы из локального сокета, упаковывает их в батчи и отправляет по WebRTC."""
            nonlocal sigstart_ev
            buffer = bytearray()
            try:
                first_recv = True
                while not pipe_closed.is_set():
                    try:
                        # 1. Ждем хотя бы один пакет (блокирующе)
                        # Если буфер уже частично заполнен предыдущими остатками, можно уменьшить таймаут (опционально)
                        data = await asyncio.wait_for(reader.read(), timeout=BATCH_TIMEOUT)
                        
                        if offerer and first_recv:
                            first_recv = False
                            await sigstart_ev.wait()

                        if not data: break
                        
                        #logger.debug("WebRTCI/UDP batcher: packed packet into frame. contents: %s", data)
                        
                        while True:
                            # framing
                            buffer.extend(len(data).to_bytes(4, 'big'))
                            buffer.extend(data)
                            
                            if len(data) > BATCH_SIZE_LIMIT:
                                break
                            
                            data = reader.read_nowait()
                            if data is None:
                                break

                        if buffer:
                            channel.send(self._handle_raw_data(bytes(buffer), chid, False, False))
                            #logger.debug("WebRTCI/UDP batcher: sent frame: %d >LIM", len(buffer))
                            buffer.clear()

                    except asyncio.TimeoutError:
                        # Тайм-аут сработал, значит новых датаграмм пока нет.
                        # Если в буфере что-то есть, отправляем.
                        if buffer:
                            if offerer and first_recv:
                                first_recv = False
                                await sigstart_ev.wait()
                            channel.send(self._handle_raw_data(bytes(buffer), chid, False, False))
                            #logger.debug("WebRTCI/UDP batcher: sent frame %d: >TIME", len(buffer))
                            buffer.clear()
                    except (ConnectionResetError, asyncio.CancelledError):
                        break
            finally:
                pipe_closed.set()
        
        incoming_messages = asyncio.Queue()
        
        async def socket_writer():
            nonlocal sigstart_ev, incoming_messages
            
            @channel.on("message")
            def on_message(message):
                nonlocal incoming_messages
                #logger.debug("WebRTCI/UDP writer: new message: %s", message)
                try:
                    incoming_messages.put_nowait(message)
                except asyncio.QueueShutDown:
                    pass

            @channel.on("close")
            def on_close():
                pipe_closed.set()

            if not offerer:
                channel.send(self._handle_raw_data(b'', chid, True, False))
            
            #logger.debug("WebRTCI/UDP writer: starting")
            
            while not pipe_closed.is_set():
                
                try:
                    message = await incoming_messages.get()
                except asyncio.QueueShutDown:
                    break
                
                #logger.debug("WebRTCI/UDP writer: got raw: %s", message)
                
                is_SSEQ, is_EOT, raw_batch = self._handle_comps_data(message, chid)
                
                #logger.debug("WebRTCI/UDP writer: decompressed: %s,%s,%s", is_SSEQ,is_EOT,raw_batch)
                
                if offerer and is_SSEQ:
                    sigstart_ev.set()
                    continue
                
                if is_EOT:
                    logger.debug("WebRTCI/UDP writer: unexpected End Of Transmission")
                    break
                
                if writer.is_closing():
                    break
                
                try:
                    
                    view = memoryview(raw_batch)
                    offset = 0
                    limit = len(view)
                    pkts_processed = 0
                    
                    while offset < limit:
                        if offset + 4 > limit:
                            logger.debug("WebRTCI: malformed UDP batch, insufficient length data")
                            break
                    
                        
                        length = int.from_bytes(view[offset:offset+4], 'big')
                        offset += 4
                        
                        if offset + length > limit:
                            logger.debug("WebRTCI: malformed UDP batch, payload shorter than specified length")
                            break
                        
                        datagram = view[offset:offset+length]
                        #logger.debug("WebRTCI/UDP writer: unpacked and sending packet %s", datagram)
                        
                        writer.write(datagram)
                        
                        offset += length
                        pkts_processed += 1                        
                        #await writer.drain()
                        #logger.debug("WebRTCI/UDP unbatcher: sent packet %d", len(datagram))
                        
                        if pkts_processed % 16 == 0:
                            await asyncio.sleep(0)
                    if pkts_processed > 0:
                        await asyncio.sleep(0)
                    #logger.debug("WebRTCI/UDP unbatcher: unbatch frame end")
                except Exception as e:
                    logger.debug("WebRTCI/UDP writer: %s during UDP socket send", e)
                    pipe_closed.set()
                #logger.debug("WebRTCI/UDP writer: closed")
            

        tasks = (asyncio.create_task(socket_reader()), asyncio.create_task(socket_writer()))
        TaskManager().add_task(tasks[0])
        TaskManager().add_task(tasks[1])
        await pipe_closed.wait()
        incoming_messages.shutdown()
        for task in tasks:
            task.cancel()
        if channel.readyState == 'open':
            channel.close()
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
        
        self._after_close(chid)
        
        logger.debug("WebRTCI: UDP pipe closed for %s", chid)
    
    async def _on_listener_connect_cb(self, port_info: tuple[int, str], reader: asyncio.StreamReader|net._UDPStreamReader, writer: asyncio.StreamWriter|net._UDPStreamWriter):
        local_addr = writer.get_extra_info("peername")
        logger.debug("WebRTCI: local connection from %s to %s", local_addr, port_info)
        chid = self._begin_proxy(port_info)
        try:
            res = await asyncio.wait_for(self.ev_waiting[chid], timeout=config.CHANNEL_CREATION_TIMEOUT)
            if res == 0: # success
                pass
            elif res == 1: # rejected
                writer.close()
                return
            else:
                logger.error("WebRTCI: invalid event answer: %s", res)
        except TimeoutError:
            self._send_timed_out(chid)
            writer.close()
            return
        if chid not in self.outcoming_channels:
            logger.debug("WebRTCI: got SUCCESS on proxy create without channel warmup")
            self._send_timed_out(chid)
            writer.close()
            return
        
        if config.ENABLE_GOST_ENCRYPTION:
            self._init_enc(chid)
        logger.debug("WebRTCI: piping %s", port_info) # ############################
        await self._do_pipe(chid, self.outcoming_channels[chid], reader, writer, offerer=True, 
                            protocol=("TCP" if port_info[1] == "TCP" else "UDP"))

    def _check_channel_name(self, chid: str) -> bool:
        if not chid.startswith(config.PROXY_CHANNEL_PREFIX):
            return False
        return check_uuid4(chid[len(config.PROXY_CHANNEL_PREFIX):])
        
    def _handle_proxify(self, data: dict):
        protocol = data.get("protocol", None)
        port = data.get("port", None)
        channel_name = data.get("uuid", None)
        if not isinstance(channel_name, str) or not self._check_channel_name(config.PROXY_CHANNEL_PREFIX+channel_name):
            logger.debug("WebRTCI: invalid BEGIN_PROXY request")
            return
        channel_name = config.PROXY_CHANNEL_PREFIX + channel_name
        if protocol != "TCP" and protocol != 'UDP':
            self._send_failed(chid=channel_name, reason="INVALID_PROTOCOL")
            return
        if not isinstance(port, int) or not (1 <= port <= 65535):
            self._send_failed(chid=channel_name, reason="INVALID_PORT")
            return
        if f"{port}:{protocol}" not in self.config.SharedPorts:
            self._send_failed(chid=channel_name, reason="ACCESS_DENIED")
            return
        
        logger.debug("WebRTCI: proxifying %s %s", channel_name, port)
        
        if self.config.UnreliableChannels:
            self.incoming_channels[channel_name] = self.conn.createDataChannel(channel_name, ordered=False, maxRetransmits=0)
        else:
            self.incoming_channels[channel_name] = self.conn.createDataChannel(channel_name)
        
        def on_open():
            TaskManager().add_task(
                asyncio.create_task(self._start_proxy(channel_name, port, protocol))
            )
        if self.incoming_channels[channel_name].readyState == "open":
            on_open()
        else:
            self.incoming_channels[channel_name].on("open", on_open)
    
    async def _start_proxy(self, chid: str, port: int, protocol: typing.Literal["TCP", "UDP"]):
        logger.debug("WebRTCI: starting remote connection to %d:%s", port, protocol)
        if protocol == 'TCP':
            reader, writer = await \
                asyncio.open_connection(host='127.0.0.1', port=port)
        else:
            reader, writer = await \
                net.create_udp_connection(host='127.0.0.1', port=port)
        if config.ENABLE_GOST_ENCRYPTION:
            self._init_enc(chid)
        await self._do_pipe(chid=chid, channel=self.incoming_channels[chid],
                            reader=reader, writer=writer, offerer=False, protocol=protocol)
            
    def _handle_success(self, data: dict):
        if not (isinstance(data.get("channel-name", None), str)):
            return
        chn = data["channel-name"]
        if chn not in self.ev_waiting:
            return
        logger.debug("WebRTCI: success to %s", chn)
        self.ev_waiting[chn].set_result(True)
        
    def _handle_failed(self, data: dict):
        chn = data.get("channel-name", None)
        reason = data.get("reason", None)
        if not isinstance(reason, str) or not isinstance(chn, str) or not self._check_channel_name(chn):
            logger.debug("WebRTCI: got invalid FAILED response")
            return
        logger.debug("WebRTCI: peer rejected channel creation: %s", chn)
        if chn in self.incoming_channels:
            if reason != "TIMEOUT":
                logger.debug("WebRTCI: invalid rejection logic")
                return
            self.incoming_channels[chn].close()
            self.incoming_channels.pop(chn, None)
        elif chn in self.outcoming_channels or chn in self.ev_waiting:
            logger.debug("WebRTCI: rejected our request: %s", reason)
            if chn in self.ev_waiting and not self.ev_waiting[chn].done():
                self.ev_waiting[chn].set_result(1)
            if chn in self.outcoming_channels:
                self.outcoming_channels[chn].close()
                self.outcoming_channels.pop(chn, None)
        else:
            logger.debug("WebRTCI: got reject on invalid channel %s", chn)
    
    def _begin_proxy(self, to_port: tuple[int, str]) -> str:
        chid = uuid4()
        msg = {
            "type": "BEGIN_PROXY",
            "port": to_port[0],
            "protocol": to_port[1],
            "uuid": chid
        }
        logger.debug("WebRTCI: offering proxy %s", chid)
        self.ev_waiting[config.PROXY_CHANNEL_PREFIX+chid] = asyncio.Future()
        if self._control_channel.readyState in ('closed', 'closing'):
            self.terminate()
        self._control_channel.send(orjson.dumps(msg))
        return config.PROXY_CHANNEL_PREFIX+chid
    
    def _send_failed(self, chid, reason):
        msg = {
            "type": "FAILED",
            "reason": reason,
            "channel-name": chid
        }
        self._control_channel.send(orjson.dumps(msg))
    def _send_timed_out(self, chid: str):
        self._send_failed(chid=chid, reason="TIMEOUT")
    def _send_success(self, chid):
        msg = {
            "type": "SUCCESS",
            "channel-name": chid
        }
        self._control_channel.send(orjson.dumps(msg))
    def _handle_raw_data(self, data: bytes, uuid, is_SSEQ: bool, is_EOT: bool):
        if is_SSEQ and is_EOT:
            logger.error("WebRTCI: invalid handler config")
        compressed = False
        _l = len(data)
        if self.config.Compression == 'lz4' and _l > 200:
            _c = lz4.frame.compress(data, compression_level=0)
            if len(_c) < _l:
                compressed = True
                data = _c
        elif self.config.Compression == 'zstd' and _l > 200 and self._zcompressor:
            _c = self._zcompressor.compress(data)
            if len(_c) < _l:
                compressed = True
                data = _c
        elif self.config.Compression == 'zstd-hc' and _l > 150 and self._zcompressor:
            _c = self._zcompressor.compress(data)
            if len(_c) < _l:
                compressed = True
                data = _c
        config_byte = ((compressed) + (is_SSEQ << 1) + (is_EOT << 2)).to_bytes(1)
        dat = config_byte+data
        if config.ENABLE_GOST_ENCRYPTION:
            try:
                dat = bytes(self._data_encp[uuid][0].encrypt(bytearray(dat)))
            except:
                logger.error("WebRTCI: GOST encrypt failed: %s", self._data_encp, exc_info=True)
        return dat
    def _handle_comps_data(self, data, uuid) -> tuple[bool, bool, bytes]:
        'returns: (IS_STARTSEQ, IS_EOT, data)'
        if config.ENABLE_GOST_ENCRYPTION:
            try:
                data = bytes(self._data_encp[uuid][1].decrypt(bytearray(data)))
            except:
                logger.error("WebRTCI: GOST decrypt failed: %s", self._data_encp, exc_info=True)
        b1 = data[0]
        is_compressed = bool(b1 & 0b1)
        contents = data[1:]
        if is_compressed:
            if self.config.Compression == 'lz4':
                contents = lz4.frame.decompress(contents)
            elif self.config.Compression == 'none':
                logger.error("WebRTCI: expected raw data, got compressed")
            elif self._zdecompressor: # zstd || zstd-hc
                contents = self._zdecompressor.decompress(contents)
        is_SSEQ = bool(b1 & 0b10)
        is_EOT = bool(b1 & 0b100)
        return (is_SSEQ, is_EOT, contents)
    def _after_close(self, chid: str):
        logger.debug("WebRTCI: %s after-close", chid)
        if config.ENABLE_GOST_ENCRYPTION:
            try:
                if chid in self._data_encp:
                    self._data_encp[chid][0].clear()
                    self._data_encp[chid][1].clear()
                    del self._data_encp[chid]
            except:
                logger.debug("WebRTCI: failed to cleanup GOST %s", self._data_encp, exc_info=True)
            else:
                logger.debug("WebRTCI: cleaned up GOST encp")
    @typing.no_type_check
    def _init_enc(self, chid: str):
        if config.ENABLE_GOST_ENCRYPTION:
            enc_key = bytearray(gostcrypto.gosthash.new("streebog256", data=f"{self._neg_key}-{chid}".encode()).digest())
            iv = uuid.UUID(chid[len(config.PROXY_CHANNEL_PREFIX):], version=4).bytes[:8]
            enc_thr = gostcrypto.gostcipher.new('kuznechik', enc_key, gostcrypto.gostcipher.MODE_CTR, init_vect=iv)
            dec_thr = gostcrypto.gostcipher.new('kuznechik', enc_key, gostcrypto.gostcipher.MODE_CTR, init_vect=iv)
            self._data_encp[chid] = (enc_thr, dec_thr)
            logger.debug("WebRTCI: initialized GOST on %s", chid)

import asyncio
import logging
import socket
import psutil

import time
from collections.abc import Callable, Awaitable

logger = logging.getLogger(__name__)


# UDP server settings
SESSION_TIMEOUT = 30.0

# ======================= PORT UTILS =======================================================

CACHE_TTL = 0.4

_last_cache_time: float = 0.0
_cached_tcp_ports: set[int] = set()
_cached_udp_ports: set[int] = set()


def _update_cache_if_needed():
    global _last_cache_time, _cached_tcp_ports, _cached_udp_ports

    now = time.monotonic()
    
    if (now - _last_cache_time) > CACHE_TTL:
        new_tcp_ports = set()
        new_udp_ports = set()
        wildcard_ips = {"0.0.0.0", "::"}

        try:
            all_connections = psutil.net_connections(kind='inet')

            for conn in all_connections:
                if conn.laddr and conn.laddr.ip in wildcard_ips:
                    if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
                        new_tcp_ports.add(conn.laddr.port)
                    elif conn.type == socket.SOCK_DGRAM:
                        new_udp_ports.add(conn.laddr.port)
            
            _cached_tcp_ports = new_tcp_ports
            _cached_udp_ports = new_udp_ports
            _last_cache_time = now
        except psutil.AccessDenied as e:
            logger.critical("Похоже, что программа запущена в операционной системе семейства *NIX. Для корректной работы требуется запустить программу от имени администратора (sudo)", exc_info=True)
        except psutil.Error as e:
            logger.error("Could not refresh port cache", exc_info=True)


def is_tcp_port_free(port: int) -> bool:
    _update_cache_if_needed()
    return port not in _cached_tcp_ports


def is_udp_port_free(port: int) -> bool:
    _update_cache_if_needed()
    return port not in _cached_udp_ports

def calc_ip(n):
    '''calc_ip(5) -> "127.0.1.6"'''
    if n >= 256 * 255 * 255:
        logger.critical("NET_IP: tried to generate ip with n=%d", n)
    octet4 = (n % 255) + 1
    octet3 = (n // 255) % 255 + 1
    octet2 = (n // (255 * 255)) % 256
    octet1 = 127
  
    return f"{octet1}.{octet2}.{octet3}.{octet4}"

# ======================= UDP SERVER =====================================================

class _UDPStreamWriter(asyncio.StreamWriter):
    def __init__(self, transport: asyncio.DatagramTransport, client_addr: tuple, protocol: '_UDPServerProtocol'):
        self._transport = transport
        self._client_addr = client_addr
        self._protocol = protocol
        self._closed = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        self._reader = None

    def write(self, data: bytes):
        if self._transport.is_closing() or self.is_closing():
            return
        self._protocol.update_session_activity(self._client_addr)
        self._transport.sendto(data, self._client_addr)

    async def drain(self):
        pass

    def close(self):
        if not self._closed.is_set():
            self._protocol._remove_session(self._client_addr)
            self._closed.set()

    async def wait_closed(self):
        await self._closed.wait()

    def is_closing(self):
        return self._closed.is_set()

    def get_extra_info(self, name: str, default=None):
        if name == 'peername':
            return self._client_addr
        return self._transport.get_extra_info(name, default)
    
    def pause_writing(self):
        logger.debug("UDPW: pauseWriting() event")
    def resume_writing(self):
        logger.debug("UDPW: resumeWriting() event")

class _UDPStreamReader(asyncio.StreamReader):
    def __init__(self):
        self._queue = asyncio.Queue()
        self._eof = False
        self._loop = asyncio.get_running_loop()
        self._reader = None

    def feed_datagram(self, data: bytes):
        if not self._eof:
            self._queue.put_nowait(data)

    def feed_eof(self):
        if not self._eof:
            self._eof = True
            self._queue.put_nowait(None)

    async def read(self, n: int = -1) -> bytes:
        if self._queue.empty() and self._eof:
            return b''
        
        data = await self._queue.get()
        if data is None:
            self._queue.put_nowait(None)
            return b''
        
        return data

class _UDPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_connection_cb: Callable[[_UDPStreamReader, _UDPStreamWriter], Awaitable[None]], loop: asyncio.AbstractEventLoop):
        self.on_connection_cb = on_connection_cb
        self.loop = loop
        self.sessions = {}
        self.transport = None
        self._cleanup_task = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        logger.debug("UDPServ: started at %s", transport.get_extra_info('sockname'))
        self._cleanup_task = self.loop.create_task(self._cleanup_sessions())

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        if self.transport is None:
            return
        if self.transport.is_closing():
            return

        session = self.sessions.get(addr)
        if not session:
            logger.debug("UDPServ: new connection from %s", addr)
            reader = _UDPStreamReader()
            writer = _UDPStreamWriter(self.transport, addr, self)
            
            session = {
                'reader': reader,
                'writer': writer,
                'last_seen': self.loop.time()
            }
            self.sessions[addr] = session
            
            self.loop.create_task(self.on_connection_cb(reader, writer))
        
        session['last_seen'] = self.loop.time()
        session['reader'].feed_datagram(data)

    def update_session_activity(self, addr: tuple):
        if addr in self.sessions:
            self.sessions[addr]['last_seen'] = self.loop.time()

    def _remove_session(self, addr: tuple):
        session = self.sessions.pop(addr, None)
        if session:
            logger.debug("UDPServ: closing %s session", addr)
            session['reader'].feed_eof()

    async def _cleanup_sessions(self):
        try:
            while True:
                await asyncio.sleep(SESSION_TIMEOUT / 2)
                now = self.loop.time()
                if len(self.sessions) > 0:
                    logger.debug("UDPServ: timeout cycle check. %d active sessions", len(self.sessions))
                
                expired_addrs = [
                    addr for addr, session in self.sessions.items()
                    if now - session['last_seen'] > SESSION_TIMEOUT
                ]
                
                for addr in expired_addrs:
                    logger.debug("UDPServ: %s session timed out", addr)
                    self._remove_session(addr)
        except asyncio.CancelledError:
            logger.debug("UDPServ: timeout task cancelled")

    def connection_lost(self, exc: Exception | None):
        logger.debug("UDPServ: stopped")
        if self._cleanup_task:
            self._cleanup_task.cancel()
        for addr in list(self.sessions.keys()):
            self._remove_session(addr)


class _UDPServer:
    def __init__(self, transport: asyncio.DatagramTransport, protocol: _UDPServerProtocol):
        self._transport = transport
        self._protocol = protocol

    def close(self):
        if not self._transport.is_closing():
            logger.debug("UDPServerProxy: stopping...")
            self._transport.close()

    async def wait_closed(self):
        if self._protocol._cleanup_task:
            while not self._protocol._cleanup_task.done():
                await asyncio.sleep(0.01)


async def start_udp_server(
    on_connection_callback: Callable[[_UDPStreamReader, _UDPStreamWriter], Awaitable[None]],
    host: str,
    port: int,
    **kwargs
) -> _UDPServer:
    loop = asyncio.get_running_loop()
    
    protocol_instance = None
    def protocol_factory():
        nonlocal protocol_instance
        protocol_instance = _UDPServerProtocol(on_connection_callback, loop)
        return protocol_instance

    transport, _ = await loop.create_datagram_endpoint(
        protocol_factory,
        local_addr=(host, port),
        **kwargs
    )
    if protocol_instance is None:
        logger.critical("UDP Server failed to start")
        raise RuntimeError("UDP Server failed to start")
    return _UDPServer(transport, protocol_instance)

# ======================= UDP CLIENT =============================================

class _UDPClientStreamWriter(asyncio.StreamWriter):
    def __init__(self, transport: asyncio.DatagramTransport, remote_addr: tuple, protocol: '_UDPClientProtocol'):
        self._transport = transport
        self._remote_addr = remote_addr
        self._protocol = protocol
        self._closed = asyncio.Event()
        self._loop = asyncio.get_running_loop()

    def write(self, data: bytes):
        if self.is_closing():
            raise ConnectionResetError("Connection closed")
        self._transport.sendto(data, self._remote_addr)

    async def drain(self):
        pass

    def close(self):
        if not self._closed.is_set():
            self._protocol.close()
            self._closed.set()

    async def wait_closed(self):
        await self._closed.wait()

    def is_closing(self):
        return self._closed.is_set()

    def get_extra_info(self, name: str, default=None):
        if name == 'peername':
            return self._remote_addr
        return self._transport.get_extra_info(name, default)

class _UDPClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, remote_addr: tuple, loop: asyncio.AbstractEventLoop):
        self._remote_addr = remote_addr
        self._loop = loop
        self._future = self._loop.create_future()
        self.transport = None
        self.reader = None
        self.writer = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        logger.debug("UDPClient: connected to %s", self._remote_addr)
        self.transport = transport
        self.reader = _UDPStreamReader()
        self.writer = _UDPClientStreamWriter(transport, self._remote_addr, self)
        self._future.set_result((self.reader, self.writer))

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        if addr == self._remote_addr:
            if self.reader:
                self.reader.feed_datagram(data)
        else:
            logger.warning("Received datagram from unexpected address: %s", addr)

    def error_received(self, exc: Exception):
        logger.error("UDP Client error: %s", exc)
        if not self._future.done():
            self._future.set_exception(exc)

    def connection_lost(self, exc: Exception | None):
        logger.debug("UDPClient: lost connection to %s", self._remote_addr)
        if self.reader:
            self.reader.feed_eof()
        if not self._future.done():
            if exc:
                self._future.set_exception(exc)
            else:
                self._future.set_exception(ConnectionResetError("Connection lost"))

    def close(self):
        if self.transport and not self.transport.is_closing():
            self.transport.close()

async def create_udp_connection(
    host: str,
    port: int,
    **kwargs
) -> tuple[_UDPStreamReader, _UDPClientStreamWriter]:
    loop = asyncio.get_running_loop()
    remote_addr = (host, port)

    protocol = _UDPClientProtocol(remote_addr, loop)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        remote_addr=remote_addr,
        **kwargs
    )

    return await protocol._future

from __future__ import annotations

import asyncio
import orjson
import logging
import typing
from dataclasses import dataclass

import config
import net
import protocol

logger = logging.getLogger(__name__)

class ServerState:
    type = "none"
class NoneServerState(ServerState):
    pass
class ConnectedServerState(ServerState):
    type = "connected"

@dataclass
class JoiningRoomServerState(ServerState):
    type = "connected/joining"
    user_name: str
    room_name: str
    room_uuid: str

@dataclass
class CreatingRoomServerState(ServerState):
    type = "connected/creating"
    user_name: str
    room_name: str

@dataclass
class InRoomServerState(ServerState):
    type = "connected/in-room"
    user_name: str
    room_name: str
    room_uuid: str
    room_members: set[str]

class AppLogic:
    def __init__(self, send_event_to_gui: typing.Callable[[dict], None]):
        self.gui_q = send_event_to_gui
        self.should_exit = asyncio.Event()
        self.queried_events: asyncio.Queue[tuple[str, dict]] = asyncio.Queue()
        self.conn_server: typing.Optional[protocol.ServerWSSClient] = None
        self.conn_p2ps: dict[str, protocol.WebRTCInstance] = {}
        self.taskMan = protocol.TaskManager()
        self.serverState: ServerState = NoneServerState()
        self.negCfg: protocol.ConnectionConfig = protocol.ConnectionConfig() # type: ignore
    
    async def exit_watchdog(self):
        logger.debug("AL: watchdog online")
        await self.should_exit.wait()
        logger.debug("AL: watchdog exit")
        
        if self.conn_server and self.conn_server.is_alive and isinstance(self.serverState, InRoomServerState):
            await self.leave_room()
        
        raise asyncio.CancelledError()

    async def cleanup(self):
        logger.debug("AL: cleaning up")
        if self.conn_server and self.conn_server.is_alive and isinstance(self.serverState, InRoomServerState):
            await self.leave_room()
        
        self.clear_state()
        self.queried_events.shutdown()
        if self.conn_server:
            if self.conn_server.is_alive:
                await self.conn_server.stop()
        self.taskMan.shutdown()
        logger.debug("AL: cleanup succeeded")
    
    def clear_state(self):
        for conn in self.conn_p2ps.values():
            if not conn.closed:
                conn.terminate(do_notify=False)
        self.conn_p2ps.clear()
    
    async def join_room(self, user_name: str, room_name: str, room_uuid: str):
        if not self.conn_server or not self.conn_server.is_alive:
            logger.warning("AL: join room called in closed WSS")
            raise EOFError
        if not isinstance(self.serverState, ConnectedServerState):
            logger.warning("AL: join room called with invalid state")
            raise EOFError
        message = {
            "type": "JOIN_ROOM",
            "user_name": user_name,
            "room_name": room_name,
            "room_uuid": room_uuid
        }
        self.update_state(JoiningRoomServerState(user_name=user_name, room_name=room_name, room_uuid=room_uuid))
        await self.conn_server.send(orjson.dumps(message), as_text=True)
    
    async def create_room(self, user_name: str, room_name: str):
        if not self.conn_server or not self.conn_server.is_alive:
            logger.warning("AL: create room called in closed WSS")
            raise EOFError
        if not isinstance(self.serverState, ConnectedServerState):
            logger.warning("AL: create room called with invalid state")
            raise EOFError
        message = {
            "type": "NEW_ROOM",
            "room_name": room_name,
            "user_name": user_name
        }
        self.update_state(CreatingRoomServerState(user_name=user_name, room_name=room_name))
        await self.conn_server.send(orjson.dumps(message), as_text=True)
    
    async def leave_room(self) -> None:
        if not self.conn_server or not self.conn_server.is_alive:
            return
        if not isinstance(self.serverState, InRoomServerState):
            return
        message = {
            "type": "LEAVE_ROOM",
            "user_name": self.serverState.user_name,
            "room_name": self.serverState.room_name,
            "room_uuid": self.serverState.room_uuid
        }
        self.clear_state()
        self.update_state(ConnectedServerState())
        self.gui_q({"type": "left_room"})
        await self.conn_server.send(orjson.dumps(message), as_text=True)
    
    async def fast_room_exact(self, user_name: str, room_name: str, room_uuid: str):
        if not self.conn_server or not self.conn_server.is_alive:
            logger.warning("AL: fastroomexact called in closed WSS")
            raise EOFError
        if not isinstance(self.serverState, ConnectedServerState):
            logger.warning("AL: fastroomexact called with invalid state")
            raise EOFError
        message = {
            "type": "FAST_ROOM_EXACT",
            "user_name": user_name,
            "room_name": room_name,
            "room_uuid": room_uuid
        }
        self.update_state(JoiningRoomServerState(user_name=user_name, room_name=room_name, room_uuid=room_uuid))
        await self.conn_server.send(orjson.dumps(message), as_text=True)
    
    async def send_sdp_state(self, target_user: str, sdp_type: str, sdp_data):
        if not self.conn_server or not self.conn_server.is_alive:
            logger.warning("AL: send sdp called in closed WSS")
            raise EOFError()
        if not isinstance(self.serverState, InRoomServerState):
            logger.warning("AL: send sdp called with invalid state")
            raise EOFError()
        message = {
            "type": "SDP_NEW_STATE",
            "room_uuid": self.serverState.room_uuid,
            "room_name": self.serverState.room_name,
            "user_name": self.serverState.user_name,
            "target_user": target_user,
            "sdp_type": sdp_type,
            "sdp_data": sdp_data
        }
        await self.conn_server.send(orjson.dumps(message), as_text=True)
    
    def authorize_request(self, data: dict) -> dict:
        if not self.conn_server or not self.conn_server.is_alive:
            return data
        if not isinstance(self.serverState, InRoomServerState):
            return data
        data["user_name"] = self.serverState.user_name
        data["room_name"] = self.serverState.room_name
        data["room_uuid"] = self.serverState.room_uuid
        return data

    async def cycle_server_recv(self) -> typing.NoReturn:
        if not self.conn_server or not self.conn_server.is_alive or isinstance(self.serverState, NoneServerState):
            logger.warning("AL: cycle server receive called in closed WSS")
            raise EOFError()
        raw = None
        while raw != b"" and not self.should_exit.is_set():
            raw = await self.conn_server.recv()
            
            try:
                js = orjson.loads(raw)
            except orjson.JSONDecodeError:
                logger.debug("AL: got invalid data from WSS, skipping")
                continue
            if not isinstance(js, dict) or 'type' not in js:
                logger.debug("AL: invalid data format got from WSS, skipping")
                continue
            
            data = js.get("data", {})
            if not isinstance(data, dict):
                data = {}
            
            match js["type"]:
                case 'FAILED':
                    reason = data.get('reason', None)
                    logger.info("AL: failed state (%s)", reason)
                    if isinstance(self.serverState, JoiningRoomServerState):
                        self.update_state(ConnectedServerState())
                        self.gui_q({"type": "left_room"})
                        if reason == "Invalid room name/UUID":
                            self.gui_q({"type": "warn", "message": "Комната с таким названием и UUID не найдена."})
                        if reason == "User with this usename already in the room":
                            self.gui_q({"type": "warn", "message": "Выберите другой псевдоним"})
                    elif isinstance(self.serverState, CreatingRoomServerState):
                        self.update_state(ConnectedServerState())
                        self.gui_q({"type": "left_room"})
                case 'SUCCESS':
                    continue
                case 'ROOM_CREATED':
                    if not isinstance(self.serverState, (CreatingRoomServerState, JoiningRoomServerState)):
                        logger.error("AL: state handling failed: got ROOM_CREATING while state is %s", self.serverState)
                        continue
                    rm_uuid = data.get("room_uuid", None)
                    if not isinstance(rm_uuid, str) or not protocol.check_uuid4(rm_uuid):
                        logger.error("AL: failed parse ROOM_CREATED")
                        continue
                    newstate = InRoomServerState(user_name=self.serverState.user_name,
                                    room_name=self.serverState.room_name, room_uuid=rm_uuid,
                                    room_members=set())
                    self.update_state(newstate)
                    self.gui_q({"type": "update_data", "upd": "roomuuid", "new": rm_uuid})
                    self.gui_q({"type": "update_data", "upd": "roomname", "new": newstate.room_name})
                    continue
                case 'ROOM_JOINED':
                    if not isinstance(self.serverState, (CreatingRoomServerState, JoiningRoomServerState)):
                        logger.error("AL: state handling failed: got ROOM_JOINED while state is %s", self.serverState)
                        continue
                    room_membs = data.get("room_members", None)
                    if not isinstance(room_membs, list):
                        logger.error("AL: failed to parse ROOM_JOINED")
                        continue
                    uname = self.serverState.user_name
                    room_membs = set(filter(lambda name: (name != uname) and
                                             not (protocol.check_username(name) is None), room_membs))
                    #logger.debug("AL: filtered room members: %s", room_membs)
                    newstate = InRoomServerState(user_name=uname, room_name=self.serverState.room_name,
                                                 room_uuid=self.serverState.room_uuid, room_members=room_membs)
                    self.update_state(newstate)
                    self.gui_q({"type": "update_data", "upd": "roomuuid", "new": newstate.room_uuid})
                    self.gui_q({"type": "update_data", "upd": "roomname", "new": newstate.room_name})
                    await self.update_p2p()
                    continue
                case 'ROOM_NEW_MEMBER':
                    if not isinstance(self.serverState, InRoomServerState):
                        logger.error("AL: state handling failed: got ROOM_NEW_MEMBER while state is %s", self.serverState)
                        continue
                    name = protocol.check_username(data.get("name", None))
                    if not isinstance(name, str):
                        logger.error("AL: failed to parse ROOM_NEW_MEMBER")
                        continue
                    if name in self.serverState.room_members:
                        logger.error("AL: member joined room again, skipped")
                        continue
                    st = self.serverState
                    st.room_members.add(name)
                    self.update_state(st)
                    await self.update_p2p(exact=name)
                    continue
                    
                case 'ROOM_MEMBER_LEFT':
                    if not isinstance(self.serverState, InRoomServerState):
                        logger.error("AL: state handling failed: got ROOM_NEW_MEMBER while state is %s", self.serverState)
                        continue
                    name = protocol.check_username(data.get("name", None))
                    if not isinstance(name, str):
                        logger.error("AL: failed to parse ROOM_NEW_MEMBER")
                        continue
                    if name not in self.serverState.room_members:
                        logger.error("AL: member left room again, skipped")
                        continue
                    st = self.serverState
                    st.room_members.remove(name)
                    self.update_state(st)
                    await self.update_p2p(exact=name)
                    continue
                
                case "SDP_STATE":
                    if not isinstance(self.serverState, InRoomServerState):
                        logger.error("AL: got SDP update while not in room")
                        continue
                    from_ = protocol.check_username(data.get("from", None))
                    sdp_type = data.get("type", None)
                    sdp_data = data.get("sdp_data", None)
                    if not isinstance(from_, str):
                        logger.error("AL: failed to parse SDP_STATE")
                        continue
                    if from_ not in self.serverState.room_members or from_ not in self.conn_p2ps:
                        logger.error("AL: got SDP update from non-existent roommate (%d %d)", from_ not in self.serverState.room_members, from_ not in self.conn_p2ps)
                        continue
                    if sdp_type not in ('offer', 'answer', 'candidate'):
                        logger.error("AL: failed to parse sdp type (SDP_STATE)")
                        continue
                    logger.debug("AL: SDP %s from %s", sdp_type, from_)
                    self.taskMan.add_task(
                        asyncio.create_task(self.conn_p2ps[from_].on_sdp(sdp_type=sdp_type, sdp_data=sdp_data))
                    )
                    continue
                
                case _:
                    logger.error("AL: invalid message type (%s), state=%s", js["type"], self.serverState)
                    continue

        if self.conn_server and self.conn_server.is_alive and self.serverState.type.startswith("connected"):
            self.clear_state()
            await self.leave_room()

        raise EOFError()
    
    def _find_free_ip(self) -> str:
        n = 0
        s = net.calc_ip(n)
        while any(s == conn.config.ShareIP for conn in self.conn_p2ps.values()):
            n += 1
            s = net.calc_ip(n)
        return s
    
    def get_config(self) -> protocol.ConnectionConfig:
        neg_config = self.negCfg
        neg_config.ShareIP = self._find_free_ip()
        return neg_config
    
    def _p2p_query(self, p2p: protocol.WebRTCInstance):
        queue = p2p.event_queue
        for ev in queue:
            #ev: tuple
            match ev[0]:
                case "exit":
                    self.conn_p2ps.pop(p2p.peer_name, None)
                    if isinstance(self.serverState, InRoomServerState):
                        if p2p.peer_name in self.serverState.room_members:
                            self.taskMan.add_task(
                                asyncio.create_task(self.update_p2p(exact=p2p.peer_name))
                            )
                case "send":
                    if len(ev) < 2:
                        logger.error("AL: got invalid event from WebRTCI")
                        continue
                    data: dict = ev[1]
                    data = self.authorize_request(data)
                    if self.conn_server and self.conn_server.is_alive and isinstance(self.serverState, InRoomServerState):
                        self.taskMan.add_task(
                            asyncio.create_task(self.conn_server.send(orjson.dumps(data), as_text=True))
                        )
                    else:
                        logger.error("AL: WebRTCI 'send' event during server disconnected")
                        continue
                case 'warn':
                    if len(ev) < 2:
                        logger.error("AL: got invalid event from WebRTCI")
                    #ev: tuple[str, str]
                    self.gui_q({"type": "warn", "message": ev[1]})
                    continue
                case "listen":
                    if len(ev) < 3:
                        logger.error("AL: got invalid event from WebRTCI")
                        continue
                    orig_port, protocol = ev[1]
                    mapped_port = ev[2]
                    mapped_ip = p2p.config.ShareIP
                    self.gui_q({"type": "add_port", "user": p2p.peer_name, "user_port": f"{orig_port}:{protocol}", "mapped": f"{mapped_ip}:{mapped_port}"})
                case "stop_listen":
                    if len(ev) < 2:
                        logger.error("AL: got invalid event from WebRTCI")
                        continue
                    orig_str = ev[1]
                    self.gui_q({"type": "rm_port", "user": p2p.peer_name, "user_port": orig_str})
                case _:
                    logger.error("AL: invalid event type from WebRTCI: %s", ev[0])
        queue.clear()
    
    async def update_p2p(self, exact: str|None = None):
        if not isinstance(self.serverState, InRoomServerState):
            logger.error("IL: tried to update p2p while not in room")
            return
        if exact is not None:
            if exact in self.serverState.room_members:
                # member joined
                if exact in self.conn_p2ps:
                    pass
                else:
                    self.conn_p2ps[exact] = protocol.WebRTCInstance(self._p2p_query, exact, 
                                                        self.serverState.user_name, self.get_config())
                    self.taskMan.add_task(asyncio.create_task(self.conn_p2ps[exact].begin()))
            else:
                # member left
                if exact in self.conn_p2ps:
                    self.conn_p2ps[exact].terminate(do_notify=True)
                else:
                    pass
            return
        else:
            for conn in self.conn_p2ps.values():
                if conn.peer_name not in self.serverState.room_members:
                    conn.terminate(do_notify=True)
                else:
                    pass
            for member in self.serverState.room_members:
                if member not in self.conn_p2ps:
                    self.conn_p2ps[member] = protocol.WebRTCInstance(self._p2p_query, member,
                                                            self.serverState.user_name, self.get_config())
                    self.taskMan.add_task(asyncio.create_task(self.conn_p2ps[member].begin()))
  
    async def post_query(self):
        while not self.queried_events.empty():
            ev = await self.queried_events.get()
            await self.handle_event_from_gui(*ev)
    
    async def server_connect(self):
        while not self.should_exit.is_set():
            logger.debug("AL: connecting to server")
            self.conn_server = protocol.ServerWSSClient()
            await self.conn_server.start()
            if self.conn_server.is_alive:
                self.update_state(ConnectedServerState())
                logger.debug("AL: connected to server, executing task")
                try:
                    await asyncio.gather(
                        self.post_query(),
                        self.cycle_server_recv(),
                        
                        return_exceptions=False
                    )
                except EOFError:
                    pass
                except asyncio.QueueShutDown:
                    pass
                except TimeoutError:
                    pass
                except Exception as e:
                    logger.error("AL: unknown error in WSS", exc_info=True)
            self.clear_state()
            await self.conn_server.stop()
            self.update_state(NoneServerState())
            logger.debug("AL: connection to WSS closed, reconnecting in 3 seconds")
            try:
                await asyncio.wait_for(self.should_exit.wait(), timeout=3)
            except TimeoutError:
                pass
            else:
                break
    
    async def run(self):
        try:
            logger.debug("AL: running tasks")
            await asyncio.gather(
                self.exit_watchdog(),
                self.server_connect(),
                
                return_exceptions=False
            )
        except asyncio.CancelledError:
            logger.debug("AL: backend finished normally")
            pass
        except Exception as e:
            logger.critical("AL: unknown exception in backend", exc_info=True)
        finally:
            await self.cleanup()
    
    async def handle_event_from_gui(self, event_type: str, data: dict):
        logger.debug("AL: event from GUI: %s %s", event_type, data)
        match event_type:
            case "connect":
                
                if not self.conn_server or not self.conn_server.is_alive or isinstance(self.serverState, NoneServerState):
                    self.gui_q({"type": "left_room"})
                    self.gui_q({"type": "warn", "message": "В данный момент подключение к серверу разорвано, пожалуйста, подождите"})
                    return
                
                username = data["username"]
                roomname = data["roomname"]
                create_new = data["create_new"]
                settings = data["settings"]
                roomuuid = data["roomuuid"]
                self.negCfg.UnreliableChannels = settings["unrel"]
                self.negCfg.Compression = settings["compression"]
                self.negCfg.ExtendedCompression = settings["ext_compression"]
                ports = settings["ports"]
                pp = []
                for port_d, proto in ports:
                    pp.append(f"{port_d}:{proto}")
                self.negCfg.SharedPorts = tuple(pp)
                
                if create_new:
                    await self.create_room(username, roomname)
                else:
                    await self.join_room(username, roomname, roomuuid)
            case "leave_room":
                await self.leave_room()
        
    def update_state(self, new_state: ServerState):
        self.serverState = new_state
        state = "неизвестно"
        if isinstance(new_state, NoneServerState):
            state = "не подключено к серверу"
        elif isinstance(new_state, ConnectedServerState):
            state = "подключено к серверу"
        elif isinstance(new_state, JoiningRoomServerState):
            state = "подключение к комнате..."
        elif isinstance(new_state, CreatingRoomServerState):
            state = "создание комнаты..."
        elif isinstance(new_state, InRoomServerState):
            state = f"подключён к комнате, членов: {len(new_state.room_members)+1}"
            
        self.gui_q({"type": "update_data", "upd": "state", "new": state})

    def shutdown(self):
        self.should_exit.set()

import time
import os
import logging
import threading
import signal
from typing import Optional, Literal
import socket
import orjson
import asyncio
import uvloop # type: ignore
uvloop.install()

logging.basicConfig(level=logging.DEBUG)
    
logging.getLogger("websockets.client").setLevel(logging.WARNING)
logging.getLogger("aioice.ice").setLevel(logging.INFO)
logging.getLogger("aiortc.rtcsctptransport").setLevel(logging.INFO)
logging.getLogger("aiortc.rtcpeerconnection").setLevel(logging.INFO)

import config
config.SERVER_MODE = True

import logic

logger = logging.getLogger("PeerPipe")

logger.info("Waiting for Suricata to boot up...")

_timeout = time.time()

while True:
    time.sleep(2)
    with open('/var/log/suricata/suricata.log', 'rt') as f:
        if 'Engine started' in f.read():
            break
    if time.time() - _timeout > 60:
        logger.critical('Suricata engine not started, exiting...')
        exit(1)

def ev_thr():
    global should_stop, loop
    while not should_stop:
        logger.info("Starting event thread...")

        SOCK_PATH = "/var/run/suricata/eve.sock"

        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) # type: ignore
        server.bind(SOCK_PATH)
        server.listen(1)

        logger.info("Waiting for Suricata...")
        conn, _ = server.accept()

        buffer = ""

        logger.debug("Suricata sock listen started")
        while not should_stop:
            data = conn.recv(4096).decode('utf-8')
            if not data:
                logger.debug("EV: breaking")
                break
            
            #logger.debug("EV: data")
            
            buffer += data
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                event = orjson.loads(line)
                if not isinstance(event, dict) or event.get('event_type', 'none') != 'alert':
                    #logger.debug("EV: skipped")
                    continue
                src_ip = event.get("src_ip")
                dest_ip = event.get("dest_ip")
                src_port = event.get("src_port")
                dest_port = event.get("dest_port")
                proto = event.get("proto")
                al = event.get("alert", {})
                sig = al.get("signature")
                sev = al.get("severity")
                if not (src_ip and dest_ip and src_port and dest_port and proto and al and sig and sev):
                    logger.debug("Invalid event fmt: %s", event)
                    continue
                
                if sev <= 2:
                    logger.info("Alert! %s:%s/%s -> %s:%s - SEVERITY=%d %s", src_ip, src_port, proto, 
                                dest_ip, dest_port, sev, sig)
                    asyncio.run_coroutine_threadsafe(handle_ev(
                        src_ip, dest_ip, src_port, dest_port, proto
                    ), loop)
    logger.debug("EV: stopped")

_thr = None


async def handle_ev(src_ip: str, dest_ip: str, src_port: int, 
                    dest_port: int, proto: Literal["TCP", "UDP"]):
    logger.debug("Initiating ban process...")
    global _app
    if not _app:
        logger.critical("Failed to handle event: AL not loaded")
        return
    client = _app.determine_interlocutor(dest_port, src_port, proto)
    if not client:
        logger.warning("Failed to determine interlocutor on AL, skipping...")
        return
    _app.banlist.add(client)
    logger.info("Banned %s", client)
    await _app.conn_p2ps[client].aterminate(do_notify=False)

_app: Optional[logic.AppLogic] = None

async def setup_tasks(app: logic.AppLogic):
    global _app
    if _app is None:
        _app = app
    logger.info("ST: Waiting server connection...")
    while not isinstance(app.serverState, logic.ConnectedServerState):
        await asyncio.sleep(0.1)
    app.negCfg.Compression = config.SET_COMPRESSION
    app.negCfg.ExtendedCompression = config.SET_EXTENDED_COMPRESSION
    app.negCfg.UnreliableChannels = config.SET_UNRELIABLE if not config.SET_EXTENDED_COMPRESSION else False
    app.negCfg.SharedPorts = config.SET_SHARE_PORTS
    app.negCfg.ShareIP = '0.0.0.0'
    logger.info("ST: Joining room...")
    await app.fast_room_exact(config.SELF, config.ROOM_NAME, config.ROOM_UUID)
    while not isinstance(app.serverState, logic.InRoomServerState):
        await asyncio.sleep(0.1)
    logger.info("ST: Success, %d members", len(app.serverState.room_members))

def _stub(*args, **kwargs):
    pass

async def main():
    global _app
    
    while not loop.is_closed():
        try:
            app = logic.AppLogic(_stub)
            _app = app
            await asyncio.gather(
                setup_tasks(app),
                app.run()
            )
            app.shutdown()
        except Exception as e:
            logger.error("AL closed: %s", e, exc_info=True)
    try:
        if _app:
            _app.shutdown()
    except:
        pass

def sig(*a, **kw):
    global _app, loop, should_stop
    logger.info("Shutting down...")
    should_stop = True
    if _app:
        _app.shutdown()
        asyncio.run_coroutine_threadsafe(_app.cleanup(), loop)
    time.sleep(0.05)
    if loop.is_running():
        loop.stop()
    exit(0)

if __name__ == "__main__":
    should_stop = False
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    signal.signal(signal.SIGTERM, sig)
    signal.signal(signal.SIGINT, sig)
    _thr = threading.Thread(target=ev_thr, daemon=True)
    _thr.start()
    try:
        loop.run_until_complete(main())
    finally:
        sig()
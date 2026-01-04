import logging
from coloredlogs import install

install(level=logging.DEBUG)
logger = logging.getLogger(__name__)

import sys

if sys.platform != "win32":
    try:
        import uvloop
        uvloop.install()
        logger.info("Using uvloop as event loop")
    except ImportError:
        logger.warning("uvloop not found, using default asyncio loop")
else:
    try:
        import winloop
        winloop.install()
        logger.info("Using winloop as event loop")
    except ImportError:
        logger.warning("winloop not found, using default asyncio loop")

import os
import orjson
import asyncio
import typing

import quart
from quart import Quart, websocket, request, Response, abort, jsonify
from quart.json.provider import DefaultJSONProvider

import protocol

T_co = typing.TypeVar("T_co", covariant=True)
class UnwrappableProxy(typing.Protocol[T_co]):
    def _get_current_object(self) -> T_co:
        ...

class ORJSONProvider(DefaultJSONProvider):
    def dumps(self, obj, **kwargs):
        return orjson.dumps(
            obj,
            option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY,
        ).decode()
    def loads(self, s: str | bytes, **kwargs):
        return orjson.loads(s)

app = Quart(__name__)
app.json = ORJSONProvider(app)

@app.route("/")
async def index():
    abort(204)

@app.websocket("/ws")
async def ws():
    raw_ws = typing.cast(UnwrappableProxy[quart.wrappers.Websocket], websocket)
    try:
        while True:
            data = await websocket.receive()
            msg: dict = orjson.loads(data)
            msg_type = msg.get("type")
            if (msg_type is None) or (msg_type not in protocol.CLIENT_MESSAGE_TYPES._S):
                await websocket.send(protocol.make_failed("Unknown message").decode())
                continue

            result: bytes = protocol.make_failed("Invalid data")            
            # DRY
            room_uuid = protocol.check_room_uuid(msg.get("room_uuid"))
            room_name = protocol.check_roomname(msg.get("room_name"))
            user_name = protocol.check_username(msg.get("user_name"))
            #logger.info("debug: %s: %s; %s; %s; %s", repr(msg), msg_type, room_uuid, room_name, user_name)
            match msg_type:
                case protocol.CLIENT_MESSAGE_TYPES.FAST_ROOM_EXACT:
                    if room_name and room_uuid and user_name:
                        result = await protocol.fast_room_exact(room_name=room_name, user_name=user_name, room_uuid=room_uuid, websock=raw_ws._get_current_object())
                case protocol.CLIENT_MESSAGE_TYPES.NEW_ROOM:
                    if room_name and user_name:
                        result = await protocol.create_room(room_name=room_name, user_name=user_name, websock=raw_ws._get_current_object())
                case protocol.CLIENT_MESSAGE_TYPES.JOIN_ROOM:
                    if room_name and room_uuid and user_name:
                       result = await protocol.join_room(room_uuid=room_uuid, room_name=room_name,
                                                          user_name=user_name, websock=raw_ws._get_current_object())
                case protocol.CLIENT_MESSAGE_TYPES.LEAVE_ROOM:
                    if room_name and room_uuid and user_name:
                       result = await protocol.leave_room(room_uuid=room_uuid, room_name=room_name,
                                                          user_name=user_name, websock=raw_ws._get_current_object())
                case protocol.CLIENT_MESSAGE_TYPES.SDP_NEW_STATE:
                    sdp_data = msg.get("sdp_data")
                    sdp_type = msg.get("sdp_type")
                    target = protocol.check_username(msg.get("target_user"))
                    if room_name and room_uuid and user_name and target and sdp_data and sdp_type in {"offer", "answer", "candidate"}:
                        result = await protocol.sdp_state(room_uuid=room_uuid, room_name=room_name, username_update_from=user_name,
                                                          username_update_to=target, offer_type=sdp_type, sdp_data=sdp_data,
                                                          websock=raw_ws._get_current_object())
                case _:
                    logger.error("Unknown message type handler: %s", msg_type)
            await websocket.send(result.decode())
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.error("Websocket error: %s", e)
    finally:
        await protocol.cleanup_client(raw_ws._get_current_object())

def ignore_ssl_error(loop, context):
    """Ignore SSL handshake errors from clients."""
    if context.get('exception').reason == "APPLICATION_DATA_AFTER_CLOSE_NOTIFY":
        return
    loop.default_exception_handler(context)

@app.before_serving
async def startup():
    """Initialize server state."""
    app.config['SECRET_KEY'] = os.urandom(24)

@app.after_serving
async def cleanup():
    protocol.rooms.clear()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.set_exception_handler(ignore_ssl_error)
    app.run(host='0.0.0.0', port=46466,
        certfile=os.path.join(os.path.dirname(__file__), "certs", "server.crt"),
        keyfile=os.path.join(os.path.dirname(__file__), "certs", "server.key"),
        debug=False,
        loop=loop)

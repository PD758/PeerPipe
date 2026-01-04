import os
import secrets
import uuid
import orjson
import typing
import logging
import asyncio
import string

logger = logging.getLogger(__name__)

import quart

Members = typing.Dict[str, quart.wrappers.Websocket]
class RoomDetails(typing.TypedDict):
    room_name: str
    members: Members

"""
{
  "room_uuid": {
    "room_name": "...",
    "members": {
      "username": websocket_connection
    }
  }
}
"""
rooms: typing.Dict[str, RoomDetails] = {}
# id(quart.wrappers.Websocket): (room_uuid, user_name)
back_table: typing.Dict[int, tuple[str, str]] = {}

def uuid4():
    return str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
def check_uuid4(u: str):
    if len(u) != 36:
        return False
    try:
        return (str(uuid.UUID(u, version=4)) == u)
    except ValueError:
        return False
    
def check_room_uuid(u: str|None) -> str|None:
    if u is None:
        return None
    if check_uuid4(u):
        return u
    return None
_ALLOWED_CHARS = frozenset(string.ascii_letters + string.digits + "_+-=/ $%#@!?,;()[]")
def check_roomname(name: str|None) -> str|None:
    if name is None:
        return None
    if not (4 <= len(name) <= 48):
        return None
    if not all(c in _ALLOWED_CHARS for c in name):
        return None
    return name
def check_username(name: str|None) -> str|None:
    if name is None:
        return None
    if not (4 <= len(name) <= 48):
        return None
    if not all(c in _ALLOWED_CHARS for c in name):
        return None
    return name

class CLIENT_MESSAGE_TYPES:
    _S = {"NEW_ROOM", "FAST_ROOM_EXACT", "JOIN_ROOM", "LEAVE_ROOM", "SDP_NEW_STATE", "SDP_CANDIDATE"}
    NEW_ROOM    = "NEW_ROOM"
    FAST_ROOM_EXACT = "FAST_ROOM_EXACT"
    JOIN_ROOM   = "JOIN_ROOM"
    LEAVE_ROOM  = "LEAVE_ROOM"
    SDP_NEW_STATE = "SDP_NEW_STATE"

CLIENT_MESSAGE_T = typing.Literal["NEW_ROOM", "FAST_ROOM_EXACT", "JOIN_ROOM", "LEAVE_ROOM", "SDP_NEW_STATE"]
SERVER_MESSAGE_T = typing.Literal["FAILED", "SUCCESS", "ROOM_CREATED", "ROOM_JOINED", "ROOM_NEW_MEMBER", 
                                  "ROOM_MEMBER_LEFT", "SDP_STATE"]

def make_message(type: SERVER_MESSAGE_T, data: dict|None) -> bytes:
    message: typing.Dict[str, typing.Any] = {
        "type": type
    }
    if data is not None:
        message["data"] = data
    return orjson.dumps(message)#.decode()
def make_failed(reason: str):
    return make_message(type="FAILED", data={
        "reason": reason
    })
def make_success():
    return make_message(type="SUCCESS", data=None)
def make_room_created(room_uuid: str):
    return make_message(type="ROOM_CREATED", data={
        "room_uuid": room_uuid
    })
def make_room_joined(room_members: list[str]):
    return make_message(type="ROOM_JOINED", data={
        "room_members": room_members
    })
def make_room_new_member(member_name: str):
    return make_message(type="ROOM_NEW_MEMBER", data={
        "name": member_name
    })
def make_room_member_left(member_name: str):
    return make_message(type="ROOM_MEMBER_LEFT", data={
        "name": member_name
    })
def make_sdp_state(offer_type: typing.Literal["offer", "answer", "candidate"], sdp_data: str, member_from: str):
    return make_message(type="SDP_STATE", data={
        "type": offer_type,
        "from": member_from,
        "sdp_data": sdp_data
    })

async def broadcast(room_uuid, message, except_: set[str]|None = None):
    if room_uuid not in rooms:
        return False
    tasks = []
    names = []
    for name, ws in rooms[room_uuid]["members"].items():
        if except_ and name in except_:
            continue
        tasks.append(ws.send(message))
        names.append(name)
    if not tasks:
        return
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for name, result in zip(names, results):
        if isinstance(result, Exception):
            logger.error(f"Failed to broadcast message to %s (room %s): %s", name, room_uuid, result)

async def send_to_peer(in_room: str, username: str, message) -> bool:
    if in_room not in rooms:
        return False
    if username not in rooms[in_room]["members"]:
        return False
    try:
        await rooms[in_room]["members"][username].send(message)
        return True
    except Exception as e:
        logger.error("Failed to send message to %s in room %s: %s", username, in_room, e, exc_info=True)
        return False

async def cleanup_client(websock):
    global rooms, back_table
    cl = back_table.pop(id(websock), ("", ""))
    if not (cl[0] and cl[1]):
        return
    if cl[0] not in rooms:
        return
    if cl[1] in rooms[cl[0]]["members"]:
        del rooms[cl[0]]["members"][cl[1]]
    if len(rooms[cl[0]]["members"]) < 1:
        del rooms[cl[0]]
    else:
        await broadcast(cl[0], make_room_member_left(cl[1]))

async def create_room(room_name: str, user_name: str, websock):
    global rooms, back_table
    if id(websock) in back_table:
        return make_failed("Conflict")
    room_uuid = uuid4()
    rooms[room_uuid] = {
        "room_name": room_name,
        "members": {
            user_name: websock
        }
    }
    back_table[id(websock)] = (room_uuid, user_name)
    return make_room_created(room_uuid)

async def join_room(room_uuid: str, room_name: str, user_name: str, websock):
    global rooms, back_table
    if id(websock) in back_table:
        return make_failed("Conflict")
    if room_uuid not in rooms:
        return make_failed("Invalid room name/UUID")
    if rooms[room_uuid]["room_name"] != room_name:
        return make_failed("Invalid room name/UUID")
    if user_name in rooms[room_uuid]["members"].keys():
        return make_failed("User with this usename already in the room")
    rooms[room_uuid]["members"][user_name] = websock
    back_table[id(websock)] = (room_uuid, user_name)
    await broadcast(room_uuid, make_room_new_member(user_name), except_={ user_name })
    return make_room_joined(list(rooms[room_uuid]["members"].keys()))

async def fast_room_exact(room_name: str, user_name: str, room_uuid: str, websock):
    global rooms, back_table
    if id(websock) in back_table:
        return make_failed("Conflict")
    if room_uuid in rooms:
        return await join_room(room_uuid=room_uuid, room_name=room_name, user_name=user_name, websock=websock)
    rooms[room_uuid] = {
        "room_name": room_name,
        "members": {
            user_name: websock
        }
    }
    back_table[id(websock)] = (room_uuid, room_name)
    return make_room_created(room_uuid)

async def leave_room(room_uuid: str, room_name: str, user_name: str, websock):
    global rooms, back_table
    if id(websock) not in back_table:
        return make_failed("Conflict")
    if room_uuid not in rooms:
        return make_failed("Invalid room name/UUID")
    if room_name != rooms[room_uuid]["room_name"]:
        return make_failed("Invalid room name/UUID")
    if user_name not in rooms[room_uuid]["members"].keys():
        return make_failed("Invalid username")
    if websock != rooms[room_uuid]["members"][user_name]:
        return make_failed("Forbidden")
    del rooms[room_uuid]["members"][user_name]
    del back_table[id(websock)]
    
    if rooms[room_uuid]["members"]:
        await broadcast(room_uuid, make_room_member_left(user_name))
    else:
        del rooms[room_uuid]
    return make_success()

async def sdp_state(room_uuid: str, room_name: str, username_update_from: str, websock,
                              username_update_to: str, offer_type: typing.Literal["offer", "answer", "candidate"], sdp_data: str):
    global rooms, back_table
    if id(websock) not in back_table:
        return make_failed("Conflict")
    if room_uuid not in rooms:
        return make_failed("Invalid room name/UUID")
    if room_name != rooms[room_uuid]["room_name"]:
        return make_failed("Invalid room name/UUID")
    if username_update_from not in rooms[room_uuid]["members"].keys():
        return make_failed("Invalid username")
    if websock != rooms[room_uuid]["members"][username_update_from]:
        return make_failed("Forbidden")
    if username_update_to not in rooms[room_uuid]["members"].keys():
        return make_failed("Not found requested user")
    if await send_to_peer(room_uuid, username_update_to,
                       make_sdp_state(offer_type, sdp_data, username_update_from)):
        return make_success()
    else:
        return make_failed("Failed to transfer offer")



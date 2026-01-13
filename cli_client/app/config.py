from typing import Optional, Literal

SERVER_URI: str = "wss://127.0.0.1:46466/ws"
DEBUG_SERVER_DISABLE_SSL: bool = True

FORCE_THEME: Optional[Literal["dark", "bright"]] = "bright"
FORCE_STYLE: Optional[Literal["fusion", "windows", "windowsvista"]] = None #"windowsvista"

ENABLE_GOST_ENCRYPTION: bool = False

ICE_SERVERS_URLS = [
    # self-hosted coturn server
    "stun:91.77.167.234:3478",
    
    # google main public stun server
    "stun:stun.l.google.com:19302",
    
    # other public servers
    "stun:stun.voipstunt.com:3478",
    "stun:stun.xten.com:3478",
    
    # other google servers
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
    "stun:stun3.l.google.com:19302",
    "stun:stun4.l.google.com:19302",
    
]

CONNECTION_TIMEOUT = 30.0 # seconds
CONTROL_CHANNEL_ID = "control-channel"
PROXY_CHANNEL_PREFIX = "proxy-"
CHANNEL_CREATION_TIMEOUT = 10.0 # seconds

SERVER_MODE = True # share ports on 0.0.0.0, linear port space
# do not use ip allocation on 127.0.0.0/8 space

### CLI SESSION
# PRECONFIGURED ROOM

SELF = "db-service-1"
ROOM_NAME = "db-share"
ROOM_UUID = "82be5bdd-f17c-4564-8472-80ecca599a60"

# PRECONFIGURED SETTINGS
SET_SHARE_PORTS = ("20000:TCP", "20001:UDP")
SET_TO_HOSTS = ("http-server.local", "127.0.0.1")
SET_UNRELIABLE = False
SET_COMPRESSION: Literal["none", "lz4", "zstd", "zstd-hc"] = "none"
SET_EXTENDED_COMPRESSION = False

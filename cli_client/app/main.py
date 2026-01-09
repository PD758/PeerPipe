import time
import os
import logging

import threading
import http.server, socketserver

import socket
import orjson
import uvloop # type: ignore
uvloop.install()

logging.basicConfig(level=logging.DEBUG)
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

logger.info("Starting...")

def test_thr():
    with socketserver.TCPServer(("", 20000), http.server.SimpleHTTPRequestHandler) as httpd:
        logger.info("Running test http server")
        httpd.serve_forever()

_thr = threading.Thread(target=test_thr, daemon=True)
_thr.start()

SOCK_PATH = "/var/run/suricata/eve.sock"

if os.path.exists(SOCK_PATH):
    os.remove(SOCK_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCK_PATH)
server.listen(1)

logger.info("Waiting for Suricata...")
conn, _ = server.accept()

buffer = ""

logger.debug("Suricata sock listen started")

while True:
    data = conn.recv(4096).decode('utf-8')
    if not data: break
    
    buffer += data
    while "\n" in buffer:
        line, buffer = buffer.split("\n", 1)
        event = orjson.loads(line)
        if not isinstance(event, dict) or event.get('event_type', 'none') != 'alert':
            continue
        # Обработка алерта
        logger.info(f"Alert! %s", event)

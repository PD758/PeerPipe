# hypercorn_config.py

# run: hypercorn -c file:server/hypercorn_config.py server/main:app

import sys
import os

bind = ["0.0.0.0:46466"]

certfile = os.path.join(os.path.dirname(__file__), "certs/", "server.crt")
keyfile = os.path.join(os.path.dirname(__file__), "certs/", "server.key")

workers = 1
loglevel = "info"
accesslog = "-" # stdout
errorlog = "-"  # stderr

if sys.platform == "win32":
    try:
        import winloop
        winloop.install()
    except ImportError:
        print("Warning: winloop not found, using default asyncio loop")
        pass

    worker_class = "asyncio"
else:
    worker_class = "uvloop"

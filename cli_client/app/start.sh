#!/bin/sh
set -e

stop_apps() {
    echo "Received SIGTERM, stopping processes..."
    kill -TERM "$PYTHON_PID" "$SURICATA_PID"
    
    wait "$PYTHON_PID"
    wait "$SURICATA_PID"
    exit 0
}

trap 'stop_apps' TERM INT

.venv/bin/python -B main.py &
PYTHON_PID=$!

IFACE=$(ifconfig | awk -F: 'NR==1{print $1}')
suricata -c /app/suricata.yaml -i "$IFACE" &
SURICATA_PID=$!

echo "Processes started: Python ($PYTHON_PID), Suricata ($SURICATA_PID)"

wait

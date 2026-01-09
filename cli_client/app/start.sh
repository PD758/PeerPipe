#!/bin/sh
set -e

.venv/bin/python main.py &

exec suricata -c /app/suricata.yaml -i $(ifconfig | awk -F: 'NR==1{print $1}')

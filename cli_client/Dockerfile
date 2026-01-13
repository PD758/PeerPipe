FROM python:3.13-slim

RUN apt-get update && apt-get install -y suricata libcap2-bin net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN suricata-update

RUN useradd -m -s /bin/bash peeruser

RUN setcap cap_net_raw,cap_net_admin,cap_sys_nice=eip /usr/bin/suricata

RUN mkdir -p /var/log/suricata /var/run/suricata /etc/suricata /var/lib/suricata && \
    chown -R peeruser:peeruser /var/log/suricata /var/run/suricata /etc/suricata /var/lib/suricata

COPY custom.rules /var/lib/suricata/rules/custom.rules
COPY app/requirements.txt /app/requirements.txt

WORKDIR /app
RUN chown -R peeruser:peeruser /app

RUN python3 -m venv .venv && chmod +x .venv/bin/activate && .venv/bin/activate && .venv/bin/pip install -r requirements.txt

RUN setcap cap_sys_ptrace,cap_dac_read_search+eip $(readlink -f .venv/bin/python)

COPY app /app
RUN chown -R peeruser:peeruser /app

USER peeruser
RUN chmod +x start.sh
CMD ["./start.sh"]

#!/usr/bin/env bash
# netmap server deploy — run as opc on the VPS, after the repo is cloned to /home/opc/netmap
set -euo pipefail
cd /home/opc/netmap

# allow an unprivileged (user-unit) process to bind port 80
echo 'net.ipv4.ip_unprivileged_port_start = 80' | sudo tee /etc/sysctl.d/99-unprivileged-ports.conf >/dev/null
sudo sysctl --system >/dev/null

# open the OS firewall (the cloud Security List must also allow tcp/80 — see README)
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --reload

mkdir -p /home/opc/var/lib/netmap

mkdir -p /home/opc/.config/systemd/user
cp deploy/netmap-ingest.service /home/opc/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now netmap-ingest.service

sleep 2
curl -fsS http://127.0.0.1/healthz && echo " <- ingest healthy"

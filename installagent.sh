# 1. Users and directories
sudo useradd --system --home /var/lib/lampa-agent --shell /usr/sbin/nologin lampa
sudo mkdir -p /opt/lampa-agent /etc/lampa-agent /var/lib/lampa-agent
sudo chown -R lampa:lampa /etc/lampa-agent /var/lib/lampa-agent

# 2. Binary (built for arm64 — check `uname -m` on the box)
#    If your dev machine is amd64:
#GOOS=linux GOARCH=arm64 go build -o agent-arm64 .
#    If you're building directly on the Armbian box, plain `go build .` is fine.
sudo cp agent /opt/lampa-agent/agent
sudo chmod 755 /opt/lampa-agent/agent

# 3. Config
sudo tee /etc/lampa-agent/agent.json >/dev/null <<'EOF'
{
  "transmission_url": "http://127.0.0.1:9091/transmission/rpc",
  "transmission_user": "transmission",
  "transmission_pass": "transmission"
}
EOF
sudo chown lampa:lampa /etc/lampa-agent/agent.json
sudo chmod 600 /etc/lampa-agent/agent.json

# 4. Service unit
sudo tee /etc/systemd/system/lampa-agent.service >/dev/null <<'EOF'
[Unit]
Description=Lampa Downloader Agent
After=network-online.target transmission-daemon.service
Wants=network-online.target

[Service]
Type=simple
User=lampa
Group=lampa
ExecStart=/opt/lampa-agent/agent -config /etc/lampa-agent/agent.json
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# 4. Create correct config file - agent.json
# Run agent as plain executable
#sudo /opt/lampa-agent/agent
# Stop agent Ctrl-C
# Edit /etc/lampa-agent/agent.json
#nano /etc/lampa-agent/agent.json
# Enter correct transmission server address (URL) and credentials (user and pass)
# Save (Ctrl-O) and exit (Ctrl-X)

# 5. Enable and start
#sudo systemctl daemon-reload
#sudo systemctl enable --now lampa-agent
#sudo systemctl status lampa-agent
#sudo journalctl -u lampa-agent -n 50
# Linux Agent Setup — SOC Lab

## Overview

This guide sets up a Linux host as a monitored Wazuh agent. Supports
Ubuntu 20.04/22.04, Debian 11/12, Kali Linux 2023+, and RHEL/CentOS 8+.

The agent will be fully monitored including: authentication events,
system calls, file integrity on critical paths, Docker logs (if applicable),
and custom application logs.

---

## Quick Deploy
```bash
# On the target Linux host:
curl -O https://raw.githubusercontent.com/yourhandle/01-enterprise-home-soc/main/scripts/setup/deploy-linux-agent.sh
chmod +x deploy-linux-agent.sh

sudo WAZUH_MANAGER=172.20.0.11 \
     WAZUH_AGENT_NAME=linux-endpoint-01 \
     WAZUH_AGENT_GROUP=linux \
     bash deploy-linux-agent.sh
```

---

## Manual Setup

### Step 1 — Add Wazuh Repository
```bash
# Debian / Ubuntu / Kali
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
  --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update

# RHEL / CentOS
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
```

### Step 2 — Install Agent
```bash
# Debian / Ubuntu / Kali
sudo WAZUH_MANAGER='172.20.0.11' \
     WAZUH_AGENT_NAME='linux-endpoint-01' \
     apt-get install wazuh-agent=4.7.3-1 -y

# RHEL / CentOS
sudo WAZUH_MANAGER='172.20.0.11' \
     WAZUH_AGENT_NAME='linux-endpoint-01' \
     yum install wazuh-agent-4.7.3-1 -y
```

### Step 3 — Apply Custom Config
```bash
# Copy the custom ossec.conf from this repo
sudo cp wazuh/agents/ossec-linux.conf /var/ossec/etc/ossec.conf
sudo chown root:ossec /var/ossec/etc/ossec.conf
sudo chmod 660 /var/ossec/etc/ossec.conf
```

### Step 4 — Start Agent
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Verify connection
sudo systemctl status wazuh-agent
sudo /var/ossec/bin/wazuh-control status
```

---

## Verify Agent Enrollment
```bash
# On the Wazuh manager (Docker host):
docker exec wazuh-manager /var/ossec/bin/agent-control -l

# Expected output:
# ID: 001, Name: linux-endpoint-01, IP: 172.20.0.100, Status: Active
```

---

## Monitored Paths (from ossec-linux.conf)

| Path | Monitoring Type | Purpose |
|------|----------------|---------|
| /var/log/auth.log | Log collection | SSH, sudo, PAM events |
| /var/log/syslog | Log collection | General system events |
| /var/log/kern.log | Log collection | Kernel events |
| /etc | FIM (realtime) | Config file integrity |
| /usr/bin, /usr/sbin | FIM (realtime) | Binary integrity |
| /boot | FIM (realtime) | Bootloader integrity |
| /root, /home | FIM (realtime) | Home directory changes |
| /var/spool/cron | FIM (realtime) | Crontab modifications |
| /var/lib/docker | Log collection | Container events |

---

## Testing the Agent
```bash
# Generate a test SSH failure (triggers rule 5760 / 100001 if repeated):
ssh invaliduser@localhost

# Check Wazuh is processing events:
sudo tail -f /var/ossec/logs/ossec.log | grep "received"

# Run a custom rule test:
# On Docker host:
python3 scripts/testing/test-rules.py --rule 100001
```

---

## Troubleshooting
```bash
# Agent not connecting?
sudo /var/ossec/bin/wazuh-control status
sudo cat /var/ossec/logs/ossec.log | tail -50 | grep -i error

# Re-enroll agent:
sudo /var/ossec/bin/manage_agents   # Interactive menu

# Check agent config is valid:
sudo /var/ossec/bin/ossec-logtest -t

# Verify manager IP is reachable:
telnet 172.20.0.11 1514
```

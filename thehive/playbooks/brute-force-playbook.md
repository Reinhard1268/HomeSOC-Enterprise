# Incident Response Playbook — Brute Force Attack
**Version:** 1.0  
**Author:** SOC Lab Project  
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing), T1078 (Valid Accounts)  
**Wazuh Rules:** 100001, 100002  
**Estimated Handling Time:** 30–90 minutes  

---

## 1. Overview

A brute force attack occurs when an adversary attempts to gain access to a system by
systematically trying large numbers of username and password combinations. This playbook
covers SSH brute force (the most common vector in Linux environments) and applies
broadly to RDP, FTP, and web application login brute force as well.

**Trigger conditions for this playbook:**
- Wazuh rule 100001 fires (10+ SSH failures in 60s from same IP)
- Wazuh rule 100002 fires (successful login after brute force — CRITICAL escalation)
- Manual escalation from monitoring staff

---

## 2. Severity Matrix

| Condition | Severity | SLA |
|-----------|----------|-----|
| Failures only, known scanner (Shodan/Censys) | Low | 24h |
| High-volume failures, unknown source IP | Medium | 4h |
| Failures targeting root or service accounts | High | 2h |
| Successful login after brute force (rule 100002) | **Critical** | **15 min** |

---

## 3. Step-by-Step Response

### Phase 1 — Detection & Triage (0–10 min)

**Step 1.1** — Confirm the alert in Wazuh Dashboard
- Navigate to: **Threat Intelligence → Events**
- Filter: `rule.id:100001 OR rule.id:100002`
- Note: `data.srcip`, `data.srcuser`, `agent.name`, `@timestamp`

**Step 1.2** — Determine attack outcome
```bash
# Check if any login from attacker IP succeeded
grep <attacker_ip> /var/log/auth.log | grep -i "accepted"
```

**Step 1.3** — Check attacker IP reputation
- [AbuseIPDB](https://www.abuseipdb.com/check/<attacker_ip>)
- [VirusTotal](https://www.virustotal.com/gui/ip-address/<attacker_ip>)
- [GreyNoise](https://viz.greynoise.io/ip/<attacker_ip>)

**Step 1.4** — Open TheHive case using `Brute Force Attack` template
- Set severity based on matrix above
- Add attacker IP and targeted account as custom fields

---

### Phase 2 — Containment (10–25 min)

**Step 2.1** — Block attacker IP immediately
```bash
# UFW (Debian/Ubuntu/Kali)
sudo ufw insert 1 deny from <attacker_ip> to any comment "IR-$(date +%Y%m%d)-BF-block"
sudo ufw status numbered

# iptables
sudo iptables -I INPUT 1 -s <attacker_ip> -j DROP -m comment --comment "IR-BF-block"
sudo iptables-save > /etc/iptables/rules.v4

# Verify the block is active
ping -c 1 <attacker_ip>  # Should still ping out — this is INBOUND block
```

**Step 2.2** — If rule 100002 fired (successful login): **Escalate to Critical**
```bash
# Immediately kill active sessions from attacker IP
sudo ss -K dst <attacker_ip>

# Lock the compromised account
sudo passwd -l <username>

# Kill all processes by that user
sudo pkill -u <username>
sudo loginctl terminate-user <username>
```

**Step 2.3** — Preserve evidence before any changes
```bash
# Save current auth log state
sudo cp /var/log/auth.log /tmp/ir-evidence-authlog-$(date +%Y%m%d%H%M%S).txt
sudo journalctl -u sshd --since "2 hours ago" > /tmp/ir-evidence-sshd-journal.txt
```

---

### Phase 3 — Investigation (25–55 min)

**Step 3.1** — If login succeeded, audit attacker activity
```bash
# Check commands run by the account
sudo cat /home/<username>/.bash_history
sudo cat /root/.bash_history

# Check for new files or downloads
sudo find / -user <username> -newer /tmp -type f 2>/dev/null | head -50

# Check for lateral movement outbound
sudo ss -tulpn | grep ESTABLISHED
sudo grep <username> /var/log/auth.log | grep -i "sudo\|su\|ssh"
```

**Step 3.2** — Check for persistence planted by attacker
```bash
sudo crontab -l -u <username> 2>/dev/null
sudo cat /etc/cron.d/*
sudo ls -la /home/<username>/.ssh/
sudo cat /home/<username>/.bashrc | grep -v "^#"
sudo getent passwd | awk -F: '$3 >= 1000 {print}'   # New accounts?
```

**Step 3.3** — Determine scope — did attacker pivot internally?
```bash
# Check for SSH from compromised host to other internal IPs
sudo grep "Accepted" /var/log/auth.log | grep -v "<attacker_ip>"
sudo last -n 30 | grep -v "still logged in"
```

**Step 3.4** — GeoIP and threat intel enrichment
```bash
# Quick GeoIP from command line
curl -s "https://ipinfo.io/<attacker_ip>/json"
```

---

### Phase 4 — Eradication (55–70 min)

**Step 4.1** — Remove attacker persistence (if any found)
```bash
# Remove unauthorized SSH keys
sudo rm -f /home/<username>/.ssh/authorized_keys
sudo rm -f /root/.ssh/authorized_keys

# Remove malicious cron jobs
sudo crontab -r -u <username>

# Remove unauthorized accounts
sudo userdel -r <unauthorized_account>
```

**Step 4.2** — Rotate credentials
```bash
# Force password reset for targeted account
sudo passwd <username>

# Rotate service account keys if targeted
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
sudo systemctl restart sshd
```

---

### Phase 5 — Recovery & Hardening (70–85 min)

**Step 5.1** — SSH hardening
```bash
sudo nano /etc/ssh/sshd_config
```
Set the following:
```
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 20
AllowUsers <specific_users_only>
Protocol 2
```
```bash
sudo sshd -t   # Test config
sudo systemctl restart sshd
```

**Step 5.2** — Install / verify fail2ban
```bash
sudo apt install fail2ban -y
sudo cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 300
EOF
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

**Step 5.3** — Verify Wazuh monitoring is operational
```bash
sudo /var/ossec/bin/wazuh-control status
sudo tail -n 20 /var/ossec/logs/ossec.log
```

---

### Phase 6 — Post-Incident (85–90 min)

**Step 6.1** — Update TheHive case
- Set all custom fields (attacker IP, targeted account, login succeeded, attempt count)
- Attach evidence files to case
- Set resolution: `True Positive` or `False Positive`

**Step 6.2** — Update IP blocklist
```bash
echo "<attacker_ip>" >> /opt/soc-lab/blocklist/ssh-brute-force-ips.txt
```

**Step 6.3** — File incident report
- Use template: `incident-reports/IR-001/IR-001-brute-force.md`

**Step 6.4** — Close the TheHive case with summary note

---

## 4. Escalation Criteria

Escalate to senior analyst / management immediately if:
- Rule 100002 fired (confirmed compromise)
- Attacker reached internal systems (lateral movement)
- Root or service account was successfully breached
- Same IP attacking multiple hosts simultaneously

---

## 5. Evidence Checklist

- [ ] Auth log extract saved with timestamps
- [ ] Attacker IP documented with reputation data
- [ ] Bash history preserved (if login succeeded)
- [ ] Block action logged with timestamp
- [ ] Firewall rule documented
- [ ] TheHive case updated with all custom fields
- [ ] Wazuh alert exported as attachment

---

## 6. References

- [MITRE T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [SSH Hardening Guide — CIS Benchmark](https://www.cisecurity.org/benchmark/distribution_independent_linux)

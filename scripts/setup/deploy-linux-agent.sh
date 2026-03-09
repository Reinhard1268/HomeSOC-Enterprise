#!/usr/bin/env bash
# =============================================================================
# deploy-linux-agent.sh — Install and register Wazuh agent on Linux endpoints
# Description: Downloads Wazuh 4.x agent, configures it to connect to the
#              Wazuh manager running in Docker, and enrolls the agent
#              automatically using the enrollment service on port 1515.
# Usage: sudo bash deploy-linux-agent.sh
# Environment vars:
#   WAZUH_MANAGER_IP   — IP of the host running Docker (default: auto-detect)
#   WAZUH_AGENT_GROUP  — Agent group name (default: linux-endpoints)
#   WAZUH_REG_PASSWORD — Registration password (default: empty)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
: "${WAZUH_MANAGER_IP:=$(hostname -I | awk '{print $1}')}"
: "${WAZUH_AGENT_GROUP:=linux-endpoints}"
: "${WAZUH_AGENT_NAME:=$(hostname)}"
: "${WAZUH_VERSION:=4.7.3}"

# ── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID}"
        DISTRO_VERSION="${VERSION_ID:-}"
    else
        error "Cannot detect Linux distribution. /etc/os-release not found."
    fi
    info "Detected: ${DISTRO_ID} ${DISTRO_VERSION}"
}

# ── Install agent ─────────────────────────────────────────────────────────────
install_agent() {
    info "Installing Wazuh agent ${WAZUH_VERSION} on ${DISTRO_ID}..."

    case "${DISTRO_ID}" in
        ubuntu|debian|kali)
            curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
                | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
                > /etc/apt/sources.list.d/wazuh.list
            apt-get update -qq
            WAZUH_MANAGER="${WAZUH_MANAGER_IP}" \
                apt-get install -y wazuh-agent
            ;;
        centos|rhel|fedora|rocky|almalinux)
            rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
            cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
enabled=1
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
EOF
            WAZUH_MANAGER="${WAZUH_MANAGER_IP}" \
                yum install -y wazuh-agent
            ;;
        *)
            error "Unsupported distribution: ${DISTRO_ID}. Install manually."
            ;;
    esac

    success "Wazuh agent package installed"
}

# ── Configure agent ───────────────────────────────────────────────────────────
configure_agent() {
    info "Configuring Wazuh agent..."

    local config_file="/var/ossec/etc/ossec.conf"

    # Backup original config
    cp "${config_file}" "${config_file}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

    cat > "${config_file}" <<EOF
<ossec_config>

  <client>
    <server>
      <address>${WAZUH_MANAGER_IP}</address>
      <port>1514</port>
      <protocol>udp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu22</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>${WAZUH_MANAGER_IP}</manager_address>
      <port>1515</port>
      <agent_name>${WAZUH_AGENT_NAME}</agent_name>
      <groups>${WAZUH_AGENT_GROUP}</groups>
    </enrollment>
  </client>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn 2>/dev/null || ss -tulpn</command>
    <frequency>360</frequency>
  </localfile>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <remove_old_diff>yes</remove_old_diff>
    <max_files_per_second>100</max_files_per_second>
    <directories check_all="yes" report_changes="yes" realtime="yes">
      /etc,/usr/bin,/usr/sbin,/bin,/sbin
    </directories>
    <directories check_all="yes">/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>
  </syscheck>

  <!-- Rootkit detection -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
  </rootcheck>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

</ossec_config>
EOF

    success "Agent configuration written to ${config_file}"
}

# ── Enable and start agent ─────────────────────────────────────────────────────
start_agent() {
    info "Enabling and starting wazuh-agent service..."
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl restart wazuh-agent
    sleep 3

    if systemctl is-active --quiet wazuh-agent; then
        success "wazuh-agent is running"
    else
        error "wazuh-agent failed to start. Check: journalctl -u wazuh-agent -n 50"
    fi
}

# ── Verify enrollment ─────────────────────────────────────────────────────────
verify_enrollment() {
    info "Waiting for agent enrollment (up to 60 seconds)..."
    local attempt=0
    while [[ $attempt -lt 12 ]]; do
        if /var/ossec/bin/agent-control -l 2>/dev/null | grep -q "${WAZUH_AGENT_NAME}"; then
            success "Agent '${WAZUH_AGENT_NAME}' enrolled successfully!"
            /var/ossec/bin/wazuh-control status
            return 0
        fi
        sleep 5
        (( attempt++ ))
    done
    warn "Could not verify enrollment automatically. Check manager dashboard."
    info "Run on manager: /var/ossec/bin/agent-control -l"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    [[ $EUID -ne 0 ]] && error "Must run as root (sudo)."

    echo ""
    info "=== Wazuh Linux Agent Deployment ==="
    info "Manager IP  : ${WAZUH_MANAGER_IP}"
    info "Agent Name  : ${WAZUH_AGENT_NAME}"
    info "Agent Group : ${WAZUH_AGENT_GROUP}"
    echo ""

    detect_distro
    install_agent
    configure_agent
    start_agent
    verify_enrollment

    echo ""
    success "Linux agent deployment complete!"
    echo "  Monitor logs: journalctl -u wazuh-agent -f"
    echo "  Agent status: /var/ossec/bin/wazuh-control status"
    echo ""
}

main "$@"

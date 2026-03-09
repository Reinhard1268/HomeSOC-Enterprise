#!/usr/bin/env bash
# =============================================================================
# backup-configs.sh — SOC Lab Configuration Backup Script
# Author: SOC Lab Project
# Description: Creates a timestamped, compressed archive of all SOC lab
#              configuration files including Wazuh rules/decoders, agent
#              configs, Elastic templates, TheHive templates, and Shuffle
#              workflows. Optionally encrypts with GPG and rotates old backups.
# Usage: bash backup-configs.sh [--encrypt] [--dest /path/to/backups]
# Schedule: Add to crontab — daily at 02:00:
#   0 2 * * * /opt/soc-lab/scripts/automation/backup-configs.sh >> /var/log/soc-lab/backup.log 2>&1
# =============================================================================

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[$(date '+%H:%M:%S')] [INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[$(date '+%H:%M:%S')] [WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[$(date '+%H:%M:%S')] [ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
: "${SOC_DIR:=$(cd "$(dirname "$0")/../.." && pwd)}"
: "${BACKUP_DEST:=/opt/soc-lab/backups}"
: "${BACKUP_RETAIN_DAYS:=30}"
: "${GPG_RECIPIENT:=}"
: "${ENCRYPT:=false}"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="soc-lab-config-backup-${TIMESTAMP}"
STAGING_DIR="/tmp/${BACKUP_NAME}"
ARCHIVE_PATH="${BACKUP_DEST}/${BACKUP_NAME}.tar.gz"
LOG_FILE="/var/log/soc-lab/backup.log"
CHECKSUM_FILE="${BACKUP_DEST}/${BACKUP_NAME}.sha256"

# ── Parse arguments ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --encrypt)
            ENCRYPT=true
            shift ;;
        --dest)
            BACKUP_DEST="$2"
            ARCHIVE_PATH="${BACKUP_DEST}/${BACKUP_NAME}.tar.gz"
            CHECKSUM_FILE="${BACKUP_DEST}/${BACKUP_NAME}.sha256"
            shift 2 ;;
        --retain)
            BACKUP_RETAIN_DAYS="$2"
            shift 2 ;;
        *)
            die "Unknown argument: $1. Usage: $0 [--encrypt] [--dest PATH] [--retain DAYS]" ;;
    esac
done

# ── Setup ──────────────────────────────────────────────────────────────────────
setup() {
    mkdir -p "${BACKUP_DEST}" "${STAGING_DIR}"
    mkdir -p "$(dirname "${LOG_FILE}")"
    info "Backup destination : ${BACKUP_DEST}"
    info "SOC Lab directory  : ${SOC_DIR}"
    info "Timestamp          : ${TIMESTAMP}"
    info "Retention          : ${BACKUP_RETAIN_DAYS} days"
}

# ── Collect project files ─────────────────────────────────────────────────────
backup_project_files() {
    info "Collecting SOC Lab project configuration files..."

    local dirs=(
        "wazuh/rules"
        "wazuh/decoders"
        "wazuh/agents"
        "elastic/index-templates"
        "elastic/saved-searches"
        "elastic/dashboards"
        "thehive/templates"
        "thehive/playbooks"
        "shuffle/workflows"
        "shuffle/integrations"
        "alerts/custom-rules"
        "alerts/tuning-reports"
        "scripts/setup"
        "scripts/automation"
        "scripts/testing"
        "atomic-red-team/scenarios"
        "architecture"
        "docs"
        "vms"
    )

    local backed_up=0
    local skipped=0

    for dir in "${dirs[@]}"; do
        local src="${SOC_DIR}/${dir}"
        if [[ -d "${src}" ]]; then
            mkdir -p "${STAGING_DIR}/${dir}"
            cp -r "${src}/." "${STAGING_DIR}/${dir}/"
            local file_count
            file_count=$(find "${src}" -type f | wc -l)
            info "  ✓ ${dir}/ (${file_count} files)"
            (( backed_up += file_count ))
        else
            warn "  ⚠ Skipping missing directory: ${dir}"
            (( skipped++ ))
        fi
    done

    success "Project files collected: ${backed_up} files, ${skipped} dirs skipped"
}

# ── Backup live Wazuh configs from Docker ─────────────────────────────────────
backup_wazuh_live_config() {
    info "Exporting live Wazuh configuration from Docker container..."

    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^wazuh-manager$"; then
        warn "wazuh-manager container not running — skipping live config export"
        return
    fi

    local wazuh_dir="${STAGING_DIR}/live-exports/wazuh"
    mkdir -p "${wazuh_dir}"

    # Export running configs
    local exports=(
        "/var/ossec/etc/ossec.conf:ossec.conf"
        "/var/ossec/etc/rules:rules-active"
        "/var/ossec/etc/decoders:decoders-active"
        "/var/ossec/etc/lists:cdb-lists"
    )

    for export in "${exports[@]}"; do
        local src="${export%%:*}"
        local dst="${export##*:}"
        if docker exec wazuh-manager test -e "${src}" 2>/dev/null; then
            docker cp "wazuh-manager:${src}" "${wazuh_dir}/${dst}" 2>/dev/null \
                && info "  ✓ Exported Wazuh ${dst}" \
                || warn "  ⚠ Failed to export Wazuh ${dst}"
        fi
    done

    # Export registered agents list
    docker exec wazuh-manager \
        /var/ossec/bin/agent-control -l 2>/dev/null \
        > "${wazuh_dir}/registered-agents.txt" \
        && info "  ✓ Exported agent list" \
        || warn "  ⚠ Could not export agent list"

    success "Live Wazuh config exported"
}

# ── Backup Elasticsearch index templates ──────────────────────────────────────
backup_elasticsearch_templates() {
    info "Exporting Elasticsearch index templates via API..."

    local es_dir="${STAGING_DIR}/live-exports/elasticsearch"
    mkdir -p "${es_dir}"

    local es_url="http://localhost:9200"
    local es_auth="${ELASTIC_PASSWORD:-ElasticAdmin_S3cur3!}"

    if ! curl -su "elastic:${es_auth}" \
            --max-time 5 "${es_url}" -o /dev/null 2>/dev/null; then
        warn "Elasticsearch not reachable — skipping template export"
        return
    fi

    # Export index templates
    curl -su "elastic:${es_auth}" \
        "${es_url}/_index_template/wazuh*" 2>/dev/null \
        | python3 -m json.tool \
        > "${es_dir}/index-templates-live.json" \
        && info "  ✓ Exported index templates" \
        || warn "  ⚠ Failed to export index templates"

    # Export ILM policies
    curl -su "elastic:${es_auth}" \
        "${es_url}/_ilm/policy/wazuh*" 2>/dev/null \
        | python3 -m json.tool \
        > "${es_dir}/ilm-policies-live.json" \
        && info "  ✓ Exported ILM policies" \
        || warn "  ⚠ Failed to export ILM policies"

    success "Elasticsearch config exported"
}

# ── Backup Docker Compose and .env (sanitised) ────────────────────────────────
backup_docker_config() {
    info "Backing up Docker Compose configuration..."

    local docker_dir="${STAGING_DIR}/docker"
    mkdir -p "${docker_dir}"

    # Copy docker-compose.yml
    if [[ -f "${SOC_DIR}/scripts/setup/docker-compose.yml" ]]; then
        cp "${SOC_DIR}/scripts/setup/docker-compose.yml" "${docker_dir}/"
        info "  ✓ docker-compose.yml"
    fi

    # Create SANITISED .env (no real secrets)
    if [[ -f "${SOC_DIR}/scripts/setup/.env" ]]; then
        sed 's/=.*/=REDACTED_SEE_VAULT/' \
            "${SOC_DIR}/scripts/setup/.env" \
            > "${docker_dir}/env.sanitised"
        info "  ✓ .env (sanitised — secrets replaced with REDACTED)"
    fi

    # Export running container versions
    docker ps --format \
        "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" \
        2>/dev/null > "${docker_dir}/running-containers.txt" \
        && info "  ✓ Running container inventory"

    success "Docker config backed up"
}

# ── Write backup manifest ─────────────────────────────────────────────────────
write_manifest() {
    info "Writing backup manifest..."

    local manifest="${STAGING_DIR}/BACKUP_MANIFEST.txt"
    local file_count
    file_count=$(find "${STAGING_DIR}" -type f | wc -l)
    local dir_count
    dir_count=$(find "${STAGING_DIR}" -type d | wc -l)

    cat > "${manifest}" << EOF
SOC LAB CONFIGURATION BACKUP MANIFEST
======================================
Backup Name    : ${BACKUP_NAME}
Created At     : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Hostname       : $(hostname)
SOC Lab Dir    : ${SOC_DIR}
Backup By User : $(whoami)
Total Files    : ${file_count}
Total Dirs     : ${dir_count}

CONTENTS
--------
$(find "${STAGING_DIR}" -type f | sed "s|${STAGING_DIR}/||" | sort)

RESTORE INSTRUCTIONS
--------------------
1. Extract: tar -xzf ${BACKUP_NAME}.tar.gz -C /opt/soc-lab-restore/
2. Review sanitised .env and restore real secrets from your vault
3. Copy configs to SOC Lab directory:
   cp -r /opt/soc-lab-restore/${BACKUP_NAME}/wazuh/* /opt/soc-lab/wazuh/
4. Reload Wazuh: docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
5. Import Elastic templates: scripts/setup/deploy.sh --skip-docker
6. Import Kibana dashboards via Kibana UI

VERIFICATION
------------
SHA256 checksum: See ${BACKUP_NAME}.sha256
EOF

    info "  ✓ Manifest written"
}

# ── Create archive ────────────────────────────────────────────────────────────
create_archive() {
    info "Creating compressed archive: ${ARCHIVE_PATH}"
    mkdir -p "${BACKUP_DEST}"

    tar -czf "${ARCHIVE_PATH}" \
        -C "/tmp" \
        "${BACKUP_NAME}/"

    local size
    size=$(du -sh "${ARCHIVE_PATH}" | cut -f1)
    success "Archive created: ${ARCHIVE_PATH} (${size})"
}

# ── Generate checksum ─────────────────────────────────────────────────────────
generate_checksum() {
    info "Generating SHA256 checksum..."
    sha256sum "${ARCHIVE_PATH}" > "${CHECKSUM_FILE}"
    local checksum
    checksum=$(cut -d' ' -f1 "${CHECKSUM_FILE}")
    success "SHA256: ${checksum}"
    info "Checksum saved to: ${CHECKSUM_FILE}"
}

# ── Optional GPG encryption ───────────────────────────────────────────────────
encrypt_archive() {
    if [[ "${ENCRYPT}" != "true" ]]; then
        return
    fi

    if ! command -v gpg &>/dev/null; then
        warn "GPG not installed — skipping encryption"
        return
    fi

    if [[ -z "${GPG_RECIPIENT}" ]]; then
        warn "GPG_RECIPIENT not set — skipping encryption"
        warn "Set: export GPG_RECIPIENT=your-gpg-key-email"
        return
    fi

    info "Encrypting archive with GPG (recipient: ${GPG_RECIPIENT})..."
    gpg --yes --batch \
        --recipient "${GPG_RECIPIENT}" \
        --encrypt "${ARCHIVE_PATH}" \
        && rm -f "${ARCHIVE_PATH}" \
        && success "Encrypted: ${ARCHIVE_PATH}.gpg" \
        || warn "GPG encryption failed — unencrypted archive kept"
}

# ── Rotate old backups ────────────────────────────────────────────────────────
rotate_old_backups() {
    info "Rotating backups older than ${BACKUP_RETAIN_DAYS} days..."
    local deleted=0

    while IFS= read -r -d '' old_file; do
        rm -f "${old_file}"
        info "  Deleted old backup: $(basename "${old_file}")"
        (( deleted++ ))
    done < <(find "${BACKUP_DEST}" \
        -name "soc-lab-config-backup-*" \
        -mtime "+${BACKUP_RETAIN_DAYS}" \
        -print0 2>/dev/null)

    if [[ $deleted -eq 0 ]]; then
        info "  No old backups to rotate"
    else
        success "Rotated ${deleted} old backup(s)"
    fi
}

# ── Cleanup staging ───────────────────────────────────────────────────────────
cleanup() {
    rm -rf "${STAGING_DIR}"
    info "Staging directory cleaned up"
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
    local archive_size
    archive_size=$(du -sh "${ARCHIVE_PATH}" 2>/dev/null | cut -f1 || echo "N/A")

    echo ""
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${GREEN}  BACKUP COMPLETE${RESET}"
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${RESET}"
    echo -e "  Archive  : ${CYAN}${ARCHIVE_PATH}${RESET}"
    echo -e "  Size     : ${archive_size}"
    echo -e "  Checksum : ${CHECKSUM_FILE}"
    echo -e "  Retain   : ${BACKUP_RETAIN_DAYS} days"
    echo ""
    echo -e "  Verify: ${DIM}sha256sum -c ${CHECKSUM_FILE}${RESET}"
    echo -e "  Extract: ${DIM}tar -xzf $(basename "${ARCHIVE_PATH}") -C /restore/${RESET}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${BOLD}${CYAN}SOC Lab Configuration Backup — ${TIMESTAMP}${RESET}"
    echo ""

    setup
    backup_project_files
    backup_wazuh_live_config
    backup_elasticsearch_templates
    backup_docker_config
    write_manifest
    create_archive
    generate_checksum
    encrypt_archive
    rotate_old_backups
    cleanup
    print_summary
}

main "$@"

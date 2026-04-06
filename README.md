<p align="center">
  <pre>
    ___    ____  ____        __
   /   |  / __ \/ __ \__  __/ /________
  / /| | / / / / /_/ / / / / / ___/ _ \
 / ___ |/ /_/ / ____/ /_/ / (__  )  __/
/_/  |_/_____/_/    \__,_/_/____/\___/
  </pre>
  <br>
  <b>Active Directory Enumeration Framework</b>
  <br><br>
  <a href="#installation"><img src="https://img.shields.io/badge/platform-Linux-blue?style=flat-square" alt="Platform"></a>
  <a href="#requirements"><img src="https://img.shields.io/badge/shell-bash-green?style=flat-square" alt="Shell"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square" alt="License"></a>
</p>

---

**ADPulse** is an interactive Bash-based framework that automates Active Directory enumeration during penetration tests and bug bounty engagements. It wraps [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) and [Impacket](https://github.com/fortra/impacket) into a single guided workflow — credential validation, protocol probing, user harvesting, share enumeration, Kerberoasting, BloodHound collection, and more.

## Features

| Category | What it does |
|---|---|
| **Protocol Probing** | Tests SMB, LDAP, WinRM, RDP, and MSSQL reachability in one pass |
| **User Enumeration** | Combines RID brute-force and LDAP user dump, deduplicates into a clean wordlist |
| **SMB Shares** | Lists all accessible shares with permission info |
| **ADCS Detection** | Identifies Certificate Authority servers and flags for Certipy follow-up |
| **Pre-Win2K Accounts** | Finds legacy accounts with weak default passwords |
| **Zerologon** | CVE-2020-1472 check with confirmation prompt (excluded from bulk runs) |
| **GPP AutoLogon** | Extracts credentials stored in Group Policy Preferences |
| **BloodHound** | Collects full AD graph data and copies the ZIP to your output folder |
| **Kerberoasting** | Standard + blind (no pre-auth) SPN hash extraction |
| **AS-REP Roasting** | Finds accounts without Kerberos pre-authentication |
| **Run All** | Executes every check (except Zerologon) in sequence |

## Requirements

- **OS:** Linux (tested on Kali, Parrot, Ubuntu)
- **NetExec (nxc):** [Installation guide](https://www.netexec.wiki/getting-started/installation)
- **Impacket:** `GetUserSPNs.py` and `GetNPUsers.py` must be in `$PATH`
- **Core utils:** `getent`, `awk`, `tee` (pre-installed on most distros)

## Installation

```bash
git clone https://github.com/BloodBlinker/ADPulse.git
cd adpulse
chmod +x adpulse.sh
```

## Usage

```bash
./adpulse.sh
```

ADPulse will walk you through:

1. **Target setup** — Enter the DC FQDN and domain name. The DC IP is resolved automatically (or enter it manually if DNS fails).
2. **Authentication** — Supply credentials for authenticated enumeration, or leave blank for anonymous mode.
3. **Module selection** — Pick individual checks from the menu or run everything at once with option `12`.

### Example Session

```
$ ./adpulse.sh

    ___    ____  ____        __
   /   |  / __ \/ __ \__  __/ /________
  / /| | / / / / /_/ / / / / / ___/ _ \
 / ___ |/ /_/ / ____/ /_/ / (__  )  __/
/_/  |_/_____/_/    \__,_/_/____/\___/
  v1.0.0
  Active Directory Enumeration Framework

[+] All dependencies verified

===== TARGET =====
[?] DC FQDN (e.g. DC01.corp.local): DC01.hacksmarter.local
[?] Domain (e.g. corp.local): hacksmarter.local
[+] DC → DC01.hacksmarter.local (10.10.10.5)
[+] Output → ./adpulse_hacksmarter.local_20260406_143022

===== AUTHENTICATION =====
[?] Username (blank for anonymous): svc_audit
[?] Password: ********
[*] Validating via SMB …
[+] Authenticated as hacksmarter.local\svc_audit

===== ENUMERATION MENU =====
  1) Protocol Reachability
  2) User Enumeration (RID + LDAP)
  ...
 12) RUN ALL
  0) Exit

[?] Option: 12
```

## Output Structure

Each run creates a timestamped directory:

```
adpulse_hacksmarter.local_20260406_143022/
├── adpulse.log             # Full terminal log
├── users.txt               # Deduplicated user list
├── ldap_users.txt          # Raw LDAP user dump
├── smb_shares.txt          # Share listing
├── adcs.txt                # ADCS results
├── pre2k.txt               # Pre-Windows 2000 accounts
├── gpp_autologon.txt       # GPP credentials
├── kerb_hashes.txt         # Kerberoast hashes
├── blind_kerb_hashes.txt   # Blind Kerberoast hashes
├── asrep_hashes.txt        # AS-REP hashes
└── *_bloodhound.zip        # BloodHound ingestor data
```

## Cracking Captured Hashes

```bash
# Kerberoast (standard + blind)
hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt

# AS-REP Roast
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Roadmap

- [ ] NTLM hash / pass-the-hash authentication
- [ ] Kerberos ticket (ccache) authentication
- [ ] LDAP signing & channel binding checks
- [ ] HTML report generation
- [ ] Parallel module execution
- [ ] LAPS password retrieval
- [ ] Delegation enumeration (unconstrained, constrained, RBCD)

## Disclaimer

This tool is intended **exclusively** for authorized security testing and educational purposes. Always obtain explicit written permission before testing any system you do not own. Unauthorized use may violate applicable laws. The author assumes no liability for misuse.

## License

[MIT](LICENSE)

## Author

**Robin Roy** — [GitHub](https://github.com/BloodBlinker)

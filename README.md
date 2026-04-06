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

**ADPulse** is an interactive Bash framework that automates Active Directory enumeration during penetration tests and bug bounty engagements. It wraps [NetExec](https://github.com/Pennyw0rth/NetExec) and [Impacket](https://github.com/fortra/impacket) into a single guided workflow — credential validation, protocol probing, user harvesting, credential hunting, Kerberoasting, BloodHound collection, and more.

## Why ADPulse?

Running AD enumeration manually means remembering dozens of `nxc` flags and Impacket syntax, copy-pasting commands, losing output across terminal tabs, and forgetting checks under time pressure. ADPulse solves this by organizing 17 enumeration modules into a logical menu, logging everything to a timestamped directory, and letting you run the full playbook with a single keystroke.

## Modules

The menu is organized by methodology phase — the order you'd actually work through an engagement.

### Recon
| # | Module | What it does |
|---|--------|-------------|
| 1 | **Protocol Reachability** | Probes SMB, LDAP, WinRM, RDP, and MSSQL in one pass |
| 2 | **SMB Signing** | Identifies hosts with signing disabled (relay targets) |
| 3 | **Password Policy** | Dumps lockout thresholds, complexity, and history rules |

### Users & Credentials
| # | Module | What it does |
|---|--------|-------------|
| 4 | **User Enumeration** | RID brute-force + LDAP dump, builds a deduplicated wordlist |
| 5 | **User Descriptions** | Searches description fields for embedded passwords |

### Shares & Policies
| # | Module | What it does |
|---|--------|-------------|
| 6 | **SMB Shares** | Lists all shares with read/write permissions |
| 7 | **GPP Passwords & AutoLogon** | Extracts credentials from Group Policy Preferences |
| 8 | **LAPS Passwords** | Retrieves local admin passwords managed by LAPS |

### AD Configuration
| # | Module | What it does |
|---|--------|-------------|
| 9 | **Delegation** | Finds unconstrained, constrained, and RBCD delegation |
| 10 | **Domain Trusts** | Maps trust relationships for cross-domain attacks |
| 11 | **Pre-Windows 2000 Accounts** | Identifies legacy accounts with weak defaults |
| 12 | **ADCS** | Detects Certificate Authority servers, flags for Certipy |

### Attack
| # | Module | What it does |
|---|--------|-------------|
| 13 | **Kerberoasting** | Standard + blind (no pre-auth) SPN hash extraction |
| 14 | **AS-REP Roasting** | Finds accounts without Kerberos pre-authentication |
| 15 | **Zerologon** | CVE-2020-1472 check with confirmation prompt |

### Collection
| # | Module | What it does |
|---|--------|-------------|
| 16 | **BloodHound Ingest** | Full AD graph collection, copies ZIP to output |
| 17 | **RUN ALL** | Executes every module (except Zerologon) sequentially |

## Requirements

- **OS:** Linux (tested on Kali, Parrot, Ubuntu)
- **NetExec (nxc):** [Installation guide](https://www.netexec.wiki/getting-started/installation)
- **Impacket:** `GetUserSPNs.py` and `GetNPUsers.py` must be in `$PATH`
- **Core utils:** `getent`, `awk`, `tee` (pre-installed on most distros)

## Installation

```bash
git clone  https://github.com/BloodBlinker/ADPulse.git
cd adpulse
chmod +x adpulse.sh
```

## Usage

```bash
./adpulse.sh
```

ADPulse walks you through three steps, then drops into the menu:

1. **Target** — DC FQDN and domain name (IP is auto-resolved)
2. **Authentication** — Credentials for authenticated mode, or blank for anonymous
3. **Enumerate** — Pick modules individually or hit `17` to run everything

### Example

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

 --- Recon ---
  1) Protocol Reachability
  2) SMB Signing (relay targets)
  3) Password Policy

 --- Users & Credentials ---
  4) User Enumeration (RID + LDAP)
  5) User Descriptions (cred hunting)

 --- Shares & Policies ---
  6) SMB Shares
  7) GPP Passwords & AutoLogon
  8) LAPS Passwords

 --- AD Configuration ---
  9) Delegation (unconstrained/constrained/RBCD)
 10) Domain Trusts
 11) Pre-Windows 2000 Accounts
 12) ADCS (Certificate Services)

 --- Attack ---
 13) Kerberoasting (standard + blind)
 14) AS-REP Roasting
 15) Zerologon (CVE-2020-1472)

 --- Collection ---
 16) BloodHound Ingest
 17) RUN ALL (excludes Zerologon)
  0) Exit

[?] Option:
```

## Output

Each run creates a timestamped directory with all findings:

```
adpulse_hacksmarter.local_20260406_143022/
├── adpulse.log              # Complete terminal log
├── users.txt                # Deduplicated user wordlist
├── rid_users.txt            # RID brute-force results
├── ldap_users.txt           # Raw LDAP user dump
├── password_policy.txt      # Domain password policy
├── user_descriptions.txt    # User descriptions
├── smb_shares.txt           # Share listing
├── relay_targets.txt        # SMB signing disabled hosts
├── delegation.txt           # Delegation findings
├── domain_trusts.txt        # Trust relationships
├── pre2k.txt                # Pre-Windows 2000 accounts
├── adcs.txt                 # ADCS results
├── laps.txt                 # LAPS passwords
├── gpp_autologon.txt        # GPP credentials
├── kerb_hashes.txt          # Kerberoast hashes
├── blind_kerb_hashes.txt    # Blind Kerberoast hashes
├── asrep_hashes.txt         # AS-REP hashes
├── zerologon.txt            # Zerologon check
└── *_bloodhound.zip         # BloodHound ingestor data
```

## Cracking Hashes

```bash
# Kerberoast (standard + blind)
hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt

# AS-REP Roast
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Roadmap

- [ ] NTLM hash / pass-the-hash authentication
- [ ] Kerberos ticket (ccache) authentication
- [ ] LDAP signing & channel binding detection
- [ ] HTML report generation
- [ ] Parallel module execution
- [ ] SCCM / MECM enumeration
- [ ] ACL misconfiguration scanning

## Disclaimer

This tool is intended **exclusively** for authorized security testing and educational purposes. Always obtain explicit written permission before testing any system you do not own. Unauthorized use may violate applicable laws. The author assumes no liability for misuse.

## License

[MIT](LICENSE)


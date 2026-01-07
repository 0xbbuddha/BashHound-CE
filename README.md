<div align="center">
  <img src="./img/bashhound_ce_logo.png" alt="BashHound Logo" width="200"/>
  
  # BashHound-CE

  **Active Directory data collector for BloodHound Community Edition written in Bash**

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![BashHound](https://img.shields.io/badge/Tool-BashHound-00E2E8.svg)](https://github.com/0xbbuddha/BashHound)


  *Bash • Fast • Stealth*

</div>

---

## Description

BashHound-CE is a BloodHound Community Edition data collector written in Bash, inspired by [RustHound](https://github.com/NH-RED-TEAM/RustHound) and [SharpHound](https://github.com/SpecterOps/SharpHound). It is designed to be compatible with Linux. It generates all the JSON files (v6 format) that can be analyzed by BloodHound CE.

**BashHound-CE vs BashHound:**
- **BashHound-CE**: Exports data in BloodHound CE format (version 6) - for BloodHound Community Edition
- **BashHound**: Exports data in legacy BloodHound format (version 5) - for classic BloodHound

BashHound was created as a technical challenge rather than for real-world use. Although the tool works, it is incomplete and not fully functional for advanced usage. Updates will be released regularly to improve it and make it increasingly functional.

---

## Usage

### Standart
```bash
bashhound-ce -d <domain.local> -u <user> -p <password> -s <dc.domain.local> 
```

### Options
```bash
-c, --collection METHOD
Collection Methods:
    All       - Collects all data (default)
    DCOnly    - Collects only from the DC (no sessions)
    Session   - Collects only sessions
    Trusts    - Collects only trusts
    ACL       - Collects only ACLs
    Group     - Collects only group memberships

--zip-only      Deletes JSON files after creating the ZIP file
--port          PORT LDAP port (default: 389 for LDAP, 636 for LDAPS)
--ldaps         Use LDAPS (TLS) - equivalent to --port 636
--no-tls        Force LDAP without TLS even on port 636
```

---

## Features & Limitations

### ✅ Supported Features
- **Core Objects**: Users, Groups, Computers, OUs, Domains, GPOs, Containers
- **Relationships**: Group memberships, ACLs, Trusts
- **Advanced**:
  - High-value group detection (well-known SIDs + adminCount)
  - GPLink parsing with inheritance and enforcement flags
  - Container export (BloodHound CE v6)
  - Compatible with any Active Directory domain

### ⚠️ Known Limitations
- **Sessions**: Session collection is not implemented (requires NetSessionEnum RPC/SMB)
  - Exports show `"Collected": true` but `"Results": []` to maintain compatibility
- **AD CS (Certificate Services)**: Not supported
  - Enterprise CAs require Windows Registry access (impossible via LDAP alone)
  - Certificate Templates parsing would require complex OID/bitfield handling
  - Recommendation: Use RustHound-CE or SharpHound for AD CS enumeration
- **DCRegistryData**: Limited to null values (no remote registry access)

### 🔧 Work in Progress
- Enhanced attribute parsing (SPN targets, delegation)
- Functional level detection
- Password policy parsing

---

## Disclaimer

<div style="border: 2px solid red; background-color: #ffe6e6; padding: 10px; border-radius: 8px;">
  All tests were carried out on the DarkZero machine on Hack The Box. “TODO” notes have been added to the code to make it compatible with any server.
</div>

---

## Related Projects

- [RustHound](https://github.com/NH-RED-TEAM/RustHound) - BloodHound collector written in Rust
- [SharpHound](https://github.com/SpecterOps/SharpHound) - Official BloodHound collector written in C#
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory relationship analysis tool

---

<div align="center">
  <sub>Made with Bash</sub>
</div>

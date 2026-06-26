# Hyperium RED-CORE v0.1.0 — Legally Evidenced Threat Engine

**Author:** Patricio Tirado — CEO, Hyperiumia
**Contact:** hyperiumia@protonmail.com
**Language:** Rust 2021 Edition
**Status:** Phase 1 Complete — Recon + Evidence Chain

---

## What Is RED-CORE?

A Red Team orchestrator that executes MITRE ATT&CK techniques and cryptographically seals every step of the kill chain, producing an immutable legal dictamen of business impact.

Not a scanner. Not a simulator. An engine that executes real techniques and documents the evidence so no executive can deny the risk.

## Phase 1 Modules (v0.1.0)

| Module | File | Purpose |
|--------|------|---------|
| Types | types.rs | 13 core data structures (Target, Evidence, Finding, Dictamen) |
| Error | error.rs | 7 centralized error types |
| Evidence Chain | evidence.rs | SHA-256 chained tamper-evident audit trail |
| MITRE Database | mitre.rs | 31 ATT&CK techniques across 6 kill chain phases |
| Impact Engine | impact.rs | Business impact calculation (financial + regulatory) |
| Compliance | compliance.rs | PCI DSS 4.0, GDPR, NIST, HIPAA, SOC 2, NIS2, PTES |
| **Recon Engine** | **recon.rs** | **TCP port scan, banner grabbing, service detection, OS fingerprint, ping sweep** |
| CLI | main.rs | Command-line interface with 8 commands |

## Recon Engine (NEW)

- TCP connect scan with configurable timeout
- Banner grabbing (SSH, HTTP, FTP, SMTP, MySQL, VNC)
- Service detection from banners + port heuristics
- OS fingerprinting (Windows/Linux/macOS) from port + banner analysis
- Network discovery (ping sweep on /24 networks)
- Evidence sealing per scan operation (MITRE T1046, T1592)

## Evidence Chain

Every action sealed with chained SHA-256. Mathematically impossible to alter historical records without detection.

## MITRE ATT&CK Coverage

31 techniques across:
- Reconnaissance (5)
- Exploitation / Initial Access (4)
- Post-Exploitation / Execution (2)
- Privilege Escalation (2)
- Credential Access (4)
- Lateral Movement (4)
- Persistence (5)
- Defense Evasion (1)
- Collection / Exfiltration / Impact (2)

## Tests

50 unit tests across 7 modules, all passing.

## CLI Commands

- `red-core info` — System info
- `red-core techniques` — List all 31 techniques
- `red-core technique T1046 --compliance` — Technique details + compliance
- `red-core authorize --client ...` — Authorization flow
- `red-core compliance` — Supported frameworks
- `red-core recon <target>` — Full reconnaissance (ports + banners + OS + evidence)
- `red-core scan <target> --ports 22,80,443` — Targeted port scan
- `red-core discover --network 192.168.1.0/24` — Network host discovery

## Roadmap

- v0.5: Exploitation module (CVE-based, vulnerability matching)
- v0.7: Post-exploitation (credential harvesting, lateral movement)
- v0.9: Persistence + full kill chain orchestration
- v1.0: Dictamen generation, dashboard, REST API, Wazuh SIEM

---

**Source code is private. Demo available upon request.**

**Hyperiumia — https://github.com/hyperiumia/hyperium-red-core**

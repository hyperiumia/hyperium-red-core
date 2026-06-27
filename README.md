# Hyperium RED-CORE v0.5.0 — Legally Evidenced Threat Engine

**Author:** Patricio Tirado — CEO, Hyperiumia
**Contact:** hyperiumia@protonmail.com
**Language:** Rust 2021 Edition
**Status:** Phase 2 Complete — Exploitation + Cleanup + State Engine

---

## What Is RED-CORE?

A Red Team orchestrator that executes MITRE ATT&CK techniques and cryptographically seals every step of the kill chain, producing an immutable legal dictamen of business impact.

Not a scanner. Not a simulator. An engine that executes real techniques and documents the evidence so no executive can deny the risk.

**Legal Principle (per Julio Tirado, Legal Counsel):**
*Ninguna acción ofensiva dejará vulnerabilidades residuales o brechas de seguridad no documentadas. Cada exploit se trackea automáticamente para sanitización.*

## Modules (v0.5.0)

| Module | File | Purpose |
|--------|------|---------|
| Types | types.rs | 13 core data structures |
| Error | error.rs | 7 centralized error types |
| Evidence Chain | evidence.rs | SHA-256 chained tamper-evident audit trail |
| MITRE Database | mitre.rs | 31 ATT&CK techniques across 6 kill chain phases |
| Impact Engine | impact.rs | Business impact calculation (financial + regulatory) |
| Compliance | compliance.rs | PCI DSS 4.0, GDPR, NIST, HIPAA, SOC 2, NIS2, PTES |
| Recon Engine | recon.rs | TCP port scan, banner grabbing, service detection, OS fingerprint |
| **Exploit Engine** | **exploit.rs** | **15 CVE-based exploitation techniques with auto-cleanup tracking** |
| **Cleanup Engine** | **cleanup.rs** | **Revert all offensive actions, generate cleanup scripts** |
| **State Engine** | **state.rs** | **Pre/post snapshots, residual detection, sanitization certificates** |
| CLI | main.rs | Command-line interface with 14 commands |

## Exploitation Techniques (15)

- T1190: Log4Shell (CVE-2021-44228), SQL Injection, File Upload RCE
- T1110: SSH Brute Force, RDP Brute Force
- T1210: EternalBlue (CVE-2017-0144), WinRM Remote Execution
- T1059: PowerShell Remoting
- T1003: SAM Database Dump, LSASS Memory Dump
- T1550.002: Pass the Hash
- T1021.001: RDP Lateral Movement
- T1053.005: Scheduled Task Persistence
- T1543.003: Malicious Windows Service
- T1505.003: Web Shell Deployment

**Every technique has create_command + cleanup_command. No residual artifacts.**

## Sanitization Certificate

After every engagement, RED-CORE generates a Sanitization Certificate:
- Pre/post system state comparison
- Residual artifact detection (tasks, services, registry, users, web shells, files)
- Cleanup score (0-100%)
- Auto-generated cleanup script
- Certificate sealed in SHA-256 evidence chain

## Tests

82 unit tests across 10 modules, all passing.

## CLI Commands (14)

red-core info System info
red-core techniques List 31 MITRE techniques
red-core technique T1046 --compliance Technique + compliance mapping
red-core authorize --client ... Authorization flow
red-core compliance Supported frameworks
red-core recon Full reconnaissance
red-core scan --ports 22,80,443 Targeted port scan
red-core discover --network 192.168.1.0/24 Network host discovery
red-core exploits List 15 exploitation techniques
red-core exploit -t T1190 -T 10.0.0.1 -p 80 Execute technique
red-core snapshot System state snapshot
red-core compare --client ... Pre/post state comparison
red-core cleanup --client ... Cleanup script + certificate
red-core killchain -T --client ... Full kill chain pipeline

text

## Roadmap

- v0.7: Post-exploitation (credential harvesting, lateral movement at scale)
- v0.9: Persistence + full kill chain orchestration
- v1.0: Dictamen generation, dashboard, REST API, Wazuh SIEM, Docker

---

**Source code is private. Demo available upon request.**

**Hyperiumia — https://github.com/hyperiumia/hyperium-red-core**

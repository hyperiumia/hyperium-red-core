# Hyperium RED-CORE v0.1.0 — Legally Evidenced Threat Engine

**Author:** Patricio Tirado — CEO, Hyperiumia
**Contact:** hyperiumia@protonmail.com
**Language:** Rust 2021 Edition
**Status:** Phase 1 — Core Modules Complete

---

## What Is RED-CORE?

A Red Team orchestrator that executes MITRE ATT&CK techniques and cryptographically seals every step of the kill chain, producing an immutable legal dictamen of business impact.

Not a scanner. Not a simulator. An engine that executes real techniques and documents the evidence so no executive can deny the risk.

## Phase 1 Modules (v0.1.0)

| Module | File | Purpose |
|--------|------|---------|
| Types | types.rs | Core data structures (Target, Evidence, Finding, Dictamen) |
| Error | error.rs | Centralized error handling |
| Evidence Chain | evidence.rs | SHA-256 chained tamper-evident audit trail |
| MITRE Database | mitre.rs | 31 ATT&CK techniques across 6 kill chain phases |
| Impact Engine | impact.rs | Business impact calculation (financial + regulatory) |
| Compliance | compliance.rs | PCI DSS 4.0, GDPR, NIST, HIPAA, SOC 2, NIS2, PTES |
| CLI | main.rs | Command-line interface with 5 commands |

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
- Collection / Exfiltration (3)
- Impact (2)

## Tests

34 unit tests across 6 modules, all passing.

## CLI Commands

- `red-core info` — System info
- `red-core techniques` — List all techniques
- `red-core technique T1046` — Technique details
- `red-core technique T1046 --compliance` — Compliance mapping
- `red-core authorize --client ...` — Authorization flow
- `red-core compliance` — Supported frameworks

## Screenshots

- 01-tests-passing.png — 34 tests all green
- 02-info.png — System info display
- 03-techniques.png — Full technique list (31)
- 04-technique-T1190.png — Exploit Public-Facing App + compliance
- 05-technique-T1003.png — LSASS Memory + compliance
- 06-compliance.png — Supported frameworks
- 07-authorize.png — Authorization flow
- 08-techniques-exploitation.png — Filtered by phase
- 09-techniques-safe.png — Safe-only filter
- 10-json-output.png — JSON output

## Roadmap

- v0.5: Recon module (network discovery, service enumeration)
- v0.7: Exploitation module (vulnerability exploitation)
- v0.9: Post-exploitation (credential harvesting, lateral movement)
- v1.0: Dictamen generation, dashboard, REST API, full kill chain

---

**Hyperiumia — https://github.com/hyperiumia/hyperium-red-core**


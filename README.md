# Hyperium RED-CORE v1.0.0 — Legally Evidenced Threat Engine

**Author:** Patricio Tirado — CEO, Hyperiumia
**Contact:** hyperiumia@protonmail.com
**Language:** Rust 2021 Edition
**Status:** v1.0.0 STABLE — All 5 Phases Complete

---

## What Is RED-CORE?

A Red Team orchestrator that executes MITRE ATT&CK techniques and cryptographically seals every step of the kill chain, producing an immutable legal dictamen of business impact.

**Legal Principle (Julio Tirado, Legal Counsel):**
*Ninguna acción ofensiva dejará vulnerabilidades residuales o brechas de seguridad no documentadas.*

## 80 MITRE ATT&CK Techniques

| Phase | Techniques | Examples |
|-------|:----------:|---------|
| Reconnaissance | 5 | Port scan, banner grab, OS fingerprint |
| Exploitation | 15 | SQLi, RCE, SSRF, EternalBlue, brute force |
| Credential Harvesting | 17 | LSASS, SAM, DCSync, Kerberoasting, SSH keys, browser, cloud |
| Lateral Movement | 12 | RDP, SMB, DCOM, WinRM, Pass-the-Hash, Pass-the-Ticket |
| AD Enumeration | 13 | Domain users, trusts, SPNs, GPO, certificates, delegation |
| Persistence | 18 | Scheduled tasks, services, registry, web shells, cron, systemd, DLL hijack |

## 18 Modules

| Module | Purpose |
|--------|---------|
| Types | 13 core data structures |
| Error | 7 centralized error types |
| Evidence Chain | SHA-256 chained tamper-evident audit trail |
| MITRE Database | 80 ATT&CK techniques across 6 kill chain phases |
| Impact Engine | Business impact calculation (financial + regulatory) |
| Compliance | PCI DSS 4.0, GDPR, NIST, HIPAA, SOC 2, NIS2, PTES |
| Recon Engine | TCP port scan, banner grabbing, service detection, OS fingerprint |
| Exploit Engine | 15 CVE-based exploitation techniques with auto-cleanup tracking |
| Credential Engine | 17 credential harvesting techniques |
| Lateral Engine | 12 lateral movement techniques |
| AD Enum Engine | 13 AD enumeration techniques + attack path identification |
| Persistence Engine | 18 persistence techniques across Windows/Linux/macOS |
| Cleanup Engine | Revert all offensive actions, generate cleanup scripts |
| State Engine | Pre/post snapshots, residual detection, sanitization certificates |
| Dictamen Engine | Full Dictamen de Impacto Tecnico generation |
| Dashboard Engine | HTML dashboard with embedded CSS |
| API Engine | REST API server (warp) with 4 endpoints |
| CLI | 21 commands |

## CLI Commands (21)

red-core info System info
red-core techniques List 80 techniques
red-core technique T1046 --compliance Technique + compliance mapping
red-core authorize --client ... Authorization flow
red-core compliance Supported frameworks
red-core recon Full reconnaissance
red-core scan --ports 22,80 Targeted port scan
red-core discover --network 192.168.1.0/24 Network host discovery
red-core exploits List 15 exploitation techniques
red-core exploit -i T1190 -T 10.0.0.1 -p 80 Execute technique
red-core credentials List 17 credential harvesting techniques
red-core lateral List 12 lateral movement techniques
red-core ad-enum List 13 AD enumeration techniques
red-core persistence List 18 persistence techniques
red-core dictamen --client ... Generate Dictamen de Impacto Tecnico
red-core dashboard Generate HTML dashboard
red-core serve Start REST API server
red-core snapshot System state snapshot
red-core compare --client ... Pre/post state comparison
red-core cleanup --client ... Cleanup script + certificate
red-core kill-chain -T ... Full kill chain pipeline

text

## REST API (v1.0.0)

| Endpoint | Method | Description |
|----------|:------:|-------------|
| /api/v1/health | GET | Health check + system info |
| /api/v1/dashboard | GET | Full HTML dashboard |
| /api/v1/techniques | GET | All 80 techniques by phase |
| /api/v1/version | GET | Version and module info |

## Dictamen de Impacto Tecnico

Automated generation includes:
- Executive summary with risk level and financial impact ($2.1M-$12.8M for CRITICAL)
- Kill chain phase analysis mapped to PTES methodology
- Automated finding generation from evidence chain
- Compliance status across 7 frameworks
- Prioritized recommendations with cost/time/risk reduction
- Sanitization verification (pre/post state comparison)
- SHA-256 dictamen hash for tamper-proof verification

## Docker

```bash
docker build -t red-core .
docker run -p 8080:8080 red-core

## REST API (v1.0.0)

| Endpoint | Method | Description |
|----------|:------:|-------------|
| /api/v1/health | GET | Health check + system info |
| /api/v1/dashboard | GET | Full HTML dashboard |
| /api/v1/techniques | GET | All 80 techniques by phase |
| /api/v1/version | GET | Version and module info |

## Dictamen de Impacto Tecnico

Automated generation includes:
- Executive summary with risk level and financial impact ($2.1M-$12.8M for CRITICAL)
- Kill chain phase analysis mapped to PTES methodology
- Automated finding generation from evidence chain
- Compliance status across 7 frameworks
- Prioritized recommendations with cost/time/risk reduction
- Sanitization verification (pre/post state comparison)
- SHA-256 dictamen hash for tamper-proof verification

## Docker

```bash
docker build -t red-core .
docker run -p 8080:8080 red-core

Tests

171 unit tests across 16 modules, all passing.


Roadmap

Version	Status	Content
v0.1.0	DONE	Recon + Evidence Chain
v0.5.0	DONE	Exploitation + Cleanup + State
v0.7.0	DONE	Credential + Lateral + AD Enum
v0.9.0	DONE	Persistence + Dictamen
v1.0.0	CURRENT	Dashboard + REST API + Docker
v1.1.0	PLANNED	OS-level integration for real target execution


Source code is private. Demo available upon request.


Hyperiumia — 
https://github.com/hyperiumia/hyperium-red-core


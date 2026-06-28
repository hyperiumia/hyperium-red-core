# INFORME TECNICO — Hyperium RED-CORE v1.0.0
## Motor de Orquestacion Ofensiva con Evidencia Criptografica

---

**Autor:** Patricio Tirado — CEO, Hyperiumia
**Contacto:** hyperiumia@protonmail.com
**Fecha:** Junio 2026
**Version:** v1.0.0 STABLE
**Repositorio Publico:** https://github.com/hyperiumia/hyperium-red-core
**Repositorio Privado:** https://github.com/hyperiumia/hyperium-red-core-source

---

## 1. Resumen Ejecutivo

Hyperium RED-CORE es un motor de orquestacion ofensiva desarrollado integramente en Rust que ejecuta 80 tecnicas del marco MITRE ATT&CK y documenta criptograficamente cada paso de la cadena de ataque. La herramienta produce un Dictamen de Impacto Tecnico automatizado con impacto financiero, estado de cumplimiento regulatorio y cadena de evidencia inmutable (SHA-256).

**Principio Juridico Fundador (Julio Tirado, Asesor Legal):**
*"Ninguna accion ofensiva dejara vulnerabilidades residuales o brechas de seguridad no documentadas."*

---

## 2. Especificaciones Tecnicas

| Parametro | Valor |
|-----------|-------|
| Lenguaje | Rust 2021 Edition |
| Version | v1.0.0 STABLE |
| Archivos fuente | 18 (.rs) + Dockerfile + docker-compose.yml |
| Lineas de codigo | 8,708 |
| Tests unitarios | 171 (0 fallos) |
| Tecnicas MITRE | 80 |
| Comandos CLI | 21 |
| Endpoints REST API | 4 |
| Frameworks compliance | 7 |
| Binario | target/release/red-core |

---

## 3. Arquitectura (18 Modulos)

### 3.1 Nucleo (Core)

| Modulo | Archivo | Lineas | Proposito |
|--------|---------|:------:|-----------|
| Types | types.rs | 249 | 13 estructuras de datos fundamentales |
| Error | error.rs | 34 | 7 tipos de error centralizados |
| Evidence Chain | evidence.rs | 355 | Cadena SHA-256 inmutable (tamper-evident) |

### 3.2 Motor MITRE y Cumplimiento

| Modulo | Archivo | Lineas | Tecnicas |
|--------|---------|:------:|:--------:|
| MITRE Database | mitre.rs | 530 | 31 |
| Impact Engine | impact.rs | 362 | — |
| Compliance | compliance.rs | 202 | — |

### 3.3 Motores de Ejecucion (6 motores, 80 tecnicas)

| Modulo | Archivo | Lineas | Tecnicas | Fase |
|--------|---------|:------:|:--------:|:----:|
| Recon Engine | recon.rs | 492 | 5 | 1 |
| Exploit Engine | exploit.rs | 595 | 15 | 2 |
| Credential Engine | credential.rs | 561 | 17 | 3 |
| Lateral Engine | lateral.rs | 463 | 12 | 3 |
| AD Enum Engine | ad_enum.rs | 522 | 13 | 3 |
| Persistence Engine | persistence.rs | 588 | 18 | 4 |

### 3.4 Automatizacion y Reportes

| Modulo | Archivo | Lineas | Proposito |
|--------|---------|:------:|-----------|
| Cleanup Engine | cleanup.rs | 231 | Revertir todas las acciones ofensivas |
| State Engine | state.rs | 521 | Snapshots pre/post, deteccion de residuos |
| Dictamen Engine | dictamen.rs | 588 | Generacion automatizada del dictamen |
| Dashboard Engine | dashboard.rs | 995 | Dashboard HTML embebido |
| API Engine | api.rs | 250 | REST API (warp) |
| CLI | main.rs | 1,170 | Interfaz de linea de comandos |

---

## 4. Las 80 Tecnicas MITRE ATT&CK

### 4.1 Reconocimiento (5 tecnicas)
- Escaneo TCP de puertos
- Banner grabbing
- Deteccion de servicios
- Fingerprint de OS
- Descubrimiento de red

### 4.2 Explotacion (15 tecnicas)
- T1190: SQL Injection, RCE, SSRF, Auth Bypass, File Upload, XXE, SSTI, Deserializacion Insegura
- T1133: Servicios remotos externos (RDP, VPN, SSH brute force)
- T1110: Fuerza bruta (password spray, credential stuffing)
- T1195: Compromiso de cadena de suministro
- T1203: Explotacion para ejecucion de cliente

### 4.3 Cosecha de Credenciales (17 tecnicas)
- T1003.001: Volcado de memoria LSASS (Mimikatz, comsvcs.dll)
- T1003.002: Volcado de base de datos SAM
- T1003.003: NTDS.dit (DCSync + Volume Shadow Copy)
- T1003.004: Extraccion de secretos LSA
- T1003.005: Extraccion de credenciales DPAPI
- T1558.001: Kerberoasting
- T1558.003: AS-REP Roasting
- T1552.001: Cosecha de claves SSH (Linux + Windows)
- T1552.004: Extraccion de credenciales de navegador
- T1552.005: Cosecha de credenciales en la nube (AWS, GCP, Azure)
- T1552.006: Extraccion de perfiles WiFi
- T1555: Extraccion de Windows Vault

### 4.4 Movimiento Lateral (12 tecnicas)
- T1021.001: Movimiento lateral via RDP
- T1021.002: SMB/Administrative Shares
- T1021.003: Movimiento lateral via DCOM
- T1021.004: WinRM + PowerShell Remoting + SSH
- T1550.002: Pass-the-Hash (PsExec, SMBExec)
- T1550.003: Pass-the-Ticket + Overpass-the-Hash
- T1047: Movimiento lateral via WMI
- T1570: Transferencia de herramientas laterales

### 4.5 Enumeracion Active Directory (13 tecnicas)
- T1087.002: Usuarios de dominio, Administradores de dominio, Registros DNS
- T1018: Computadoras de dominio
- T1482: Confianzas de dominio + Confianzas de bosque
- T1558: Enumeracion SPN Kerberoastable
- T1558: Enumeracion de cuentas AS-REP Roastable
- T1069.002: Enumeracion GPO + Estructura OU
- T1557: Enumeracion de delegacion sin restricciones
- T1649: Enumeracion de plantillas de certificado (ESC1-ESC8)
- T1207: Enumeracion de politicas Kerberos

### 4.6 Persistencia (18 tecnicas)
- T1053.005: Tareas programadas (schtasks + PowerShell)
- T1543.003: Creacion de servicio Windows
- T1547.001: Registry Run Keys (HKCU + HKLM) + Carpeta de inicio
- T1505.003: Web Shells (PHP + ASPX)
- T1574.001: Secuestro de DLL
- T1546.003: Suscripcion de eventos WMI
- T1546.015: Secuestro de objeto COM
- T1053.003: Cron Jobs (usuario + sistema)
- T1543.002: Servicio Systemd
- T1037.004: Persistencia RC Local
- T1546.004: Persistencia Bash Profile
- T1543.001: Launch Daemon (macOS)

---

## 5. Comandos CLI (21)

### 5.1 Informacion del Sistema
red-core info Informacion del sistema
red-core techniques Listar 80 tecnicas
red-core technique T1046 --compliance Tecnica + mapeo de cumplimiento
red-core authorize --client ... Flujo de autorizacion
red-core compliance Frameworks soportados

text

### 5.2 Reconocimiento

### 5.2 Reconocimiento
red-core recon Reconocimiento completo
red-core scan --ports 22,80 Escaneo de puertos dirigido
red-core discover --network 192.168.1.0/24 Descubrimiento de hosts

text

### 5.3 Explotacion

### 5.3 Explotacion
red-core exploits Listar 15 tecnicas de explotacion
red-core exploit -i T1190 -T 10.0.0.1 -p 80 Ejecutar tecnica

text

### 5.4 Post-Explotacion

### 5.4 Post-Explotacion
red-core credentials 17 tecnicas de cosecha de credenciales
red-core lateral 12 tecnicas de movimiento lateral
red-core ad-enum 13 tecnicas de enumeracion AD
red-core persistence 18 tecnicas de persistencia

text

### 5.5 Dictamen y Reportes

### 5.5 Dictamen y Reportes
red-core dictamen --client ... --authorized-by ... Generar Dictamen de Impacto Tecnico
red-core dashboard Generar dashboard HTML
red-core serve Iniciar servidor REST API

text

### 5.6 Limpieza y Estado

### 5.6 Limpieza y Estado
red-core snapshot Snapshot de estado del sistema
red-core compare --client ... Comparacion estado pre/post
red-core cleanup --client ... Script de limpieza + certificado
red-core kill-chain -T ... Pipeline completo de cadena de ataque

text

---

## 6. REST API (v1.0.0)

| Endpoint | Metodo | Descripcion |
|----------|:------:|-------------|
| /api/v1/health | GET | Health check + informacion del sistema |
| /api/v1/dashboard | GET | Dashboard HTML completo |
| /api/v1/techniques | GET | 80 tecnicas por fase |
| /api/v1/version | GET | Version e informacion de modulos |

---

## 7. Dictamen de Impacto Tecnico

El motor de dictamenes genera automaticamente:

1. **Resumen ejecutivo** con nivel de riesgo (CRITICAL/HIGH/MEDIUM/LOW) e impacto financiero
2. **Analisis de fases** de cadena de ataque mapeado a PTES
3. **Hallazgos automatizados** generados desde la cadena de evidencia
4. **Estado de cumplimiento** en 7 frameworks
5. **Recomendaciones priorizadas** con estimaciones de costo/tiempo/reduccion de riesgo
6. **Verificacion de sanitizacion** (comparacion estado pre/post)
7. **Hash del dictamen** SHA-256 para verificacion antimanipulacion

### Impacto Financiero por Nivel de Riesgo

| Nivel | Impacto Minimo | Impacto Maximo |
|-------|---------------:|---------------:|
| CRITICAL | $2,100,000 | $12,800,000 |
| HIGH | $500,000 | $4,200,000 |
| MEDIUM | $100,000 | $800,000 |
| LOW | $25,000 | $150,000 |

---

## 8. Frameworks de Cumplimiento (7)

| Framework | Controles |
|-----------|:---------:|
| PCI DSS 4.0 | 8 |
| GDPR | 3 |
| NIST SP 800-53 | 6 |
| HIPAA | 4 |
| SOC 2 | 4 |
| NIS2 | 3 |
| PTES | 5 |

---

## 9. Docker

### Construccion y ejecucion
```bash
docker build -t red-core .
docker run -p 8080:8080 red-core

---

## 6. REST API (v1.0.0)

| Endpoint | Metodo | Descripcion |
|----------|:------:|-------------|
| /api/v1/health | GET | Health check + informacion del sistema |
| /api/v1/dashboard | GET | Dashboard HTML completo |
| /api/v1/techniques | GET | 80 tecnicas por fase |
| /api/v1/version | GET | Version e informacion de modulos |

---

## 7. Dictamen de Impacto Tecnico

El motor de dictamenes genera automaticamente:

1. **Resumen ejecutivo** con nivel de riesgo (CRITICAL/HIGH/MEDIUM/LOW) e impacto financiero
2. **Analisis de fases** de cadena de ataque mapeado a PTES
3. **Hallazgos automatizados** generados desde la cadena de evidencia
4. **Estado de cumplimiento** en 7 frameworks
5. **Recomendaciones priorizadas** con estimaciones de costo/tiempo/reduccion de riesgo
6. **Verificacion de sanitizacion** (comparacion estado pre/post)
7. **Hash del dictamen** SHA-256 para verificacion antimanipulacion

### Impacto Financiero por Nivel de Riesgo

| Nivel | Impacto Minimo | Impacto Maximo |
|-------|---------------:|---------------:|
| CRITICAL | $2,100,000 | $12,800,000 |
| HIGH | $500,000 | $4,200,000 |
| MEDIUM | $100,000 | $800,000 |
| LOW | $25,000 | $150,000 |

---

## 8. Frameworks de Cumplimiento (7)

| Framework | Controles |
|-----------|:---------:|
| PCI DSS 4.0 | 8 |
| GDPR | 3 |
| NIST SP 800-53 | 6 |
| HIPAA | 4 |
| SOC 2 | 4 |
| NIS2 | 3 |
| PTES | 5 |

---

## 9. Docker

### Construccion y ejecucion
```bash
docker build -t red-core .
docker run -p 8080:8080 red-core

Docker Compose
bash
docker-compose up -d
docker-compose up -d

El Dockerfile utiliza multi-stage build:

Stage 1: rust:1.77-bookworm (compilacion)
Stage 2: debian:bookworm-slim (produccion)
Usuario no-root, healthcheck, EXPOSE 8080


10. Seguridad de la Cadena de Evidencia

Cada accion ejecutada por RED-CORE se sella en una cadena criptografica SHA-256 donde cada entrada contiene:

Hash de la entrada anterior (prev_hash)
Hash del output de la accion (output_hash)
Hash de la entrada completa (chain_hash)
Timestamp, tecnica, objetivo, resultado, severidad

La cadena es verificable: cualquier manipulacion invalida todos los hashes subsiguientes.



11. Roadmap

Version	Estado	Contenido
v0.1.0	COMPLETADO	Recon + Evidence Chain
v0.5.0	COMPLETADO	Exploitation + Cleanup + State
v0.7.0	COMPLETADO	Credential + Lateral + AD Enum
v0.9.0	COMPLETADO	Persistence + Dictamen
v1.0.0	ACTUAL	Dashboard + REST API + Docker
v1.1.0	PLANIFICADO	Integracion OS-level para ejecucion contra targets reales


12. Contacto

Patricio Tirado — CEO, Hyperiumia
Email:
hyperiumia@protonmail.com
GitHub Publico:
https://github.com/hyperiumia/hyperium-red-core
GitHub Privado:
https://github.com/hyperiumia/hyperium-red-core-source



Documento generado automaticamente por Hyperium RED-CORE v1.0.0Cadena de evidencia SHA-256 verificable

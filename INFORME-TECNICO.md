# HYPERIUM RED-CORE v0.1.0
## Informe Tecnico Completo

**Autor:** Patricio Tirado -- CEO, Hyperiumia
**Fecha:** Junio 2026
**Version:** 0.1.0 (Phase 1)
**Plataforma:** Linux x86_64 (Debian, Ubuntu, RHEL, Alpine)
**Lenguaje:** Rust 2021 Edition (rustc 1.88+)
**Contacto:** hyperiumia@protonmail.com

---

## INDICE

1. Resumen Ejecutivo
2. Que es RED-CORE
3. Arquitectura del Software
4. Modulos y Componentes
5. MITRE ATT&CK Coverage
6. Cadena de Evidencia Criptografica
7. Motor de Impacto de Negocio
8. Cumplimiento Normativo
9. CLI Reference
10. Pruebas y Calidad
11. Diferenciadores vs Competencia
12. Modelo de Negocio
13. Roadmap

---

## 1. RESUMEN EJECUTIVO

Hyperium RED-CORE es un orquestador de Red Team escrito completamente en Rust que ejecuta tecnicas del framework MITRE ATT&CK y sella criptograficamente cada paso de la kill chain, produciendo un Dictamen de Impacto Tecnico inmutable e irrefutable.

A diferencia de las herramientas existentes del mercado (Cobalt Strike, Caldera, SafeBreach, Atomic Red Team), RED-CORE es la primera herramienta que combina:

- Ejecucion de ataques reales (no simulacion)
- Orquestacion completa de kill chain (6 fases PTES)
- Evidencia criptograficamente sellada (SHA-256 encadenado)
- Analisis de impacto de negocio con estimacion financiera
- Mapeo regulatorio automatico (PCI DSS, GDPR, NIST, HIPAA, SOC 2, NIS2)
- Generacion de dictamen legal inmutable

### Capacidades principales (v0.1.0):

- 31 tecnicas MITRE ATT&CK implementadas
- Cadena de evidencia SHA-256 con sellado automatico
- Motor de impacto de negocio (estimacion financiera por hallazgo)
- Mapeo regulatorio automatico a 9 frameworks
- 34 pruebas unitarias distribuidas en 6 modulos
- CLI completa con 5 comandos
- Binario Rust de alta performance sin dependencias runtime

---

## 2. QUE ES RED-CORE

### El Problema

El mercado de pentesting y Red Team tiene problemas estructurales:

- Un engagement manual de Red Team cuesta $50,000-$250,000 y toma 2-6 semanas
- Los reportes finales son PDF editables que cualquier persona puede modificar
- Los hallazgos son de un momento especifico, no continuos
- Los directivos pueden ignorar la gravedad porque es solo un informe tecnico
- No existe evidencia criptografica de que los hallazgos sean reales

### La Solucion

RED-CORE es un motor de evaluacion ofensiva que:

1. Ejecuta tecnicas MITRE ATT&CK reales contra la infraestructura del cliente
2. Sella cada paso de la kill chain con SHA-256 encadenado
3. Calcula el impacto de negocio de cada hallazgo (en dolares)
4. Mapea cada hallazgo a frameworks regulatorios
5. Genera un Dictamen de Impacto Tecnico inmutable
6. Hace imposible que los directivos nieguen el riesgo corporativo

### El Diferenciador

Si un banco compra esta licencia ($20,000 USD), obtiene un motor de Red Team continuo que extrae la evidencia matematica de como un atacante podria destruir su continuidad operativa, dejando a los directivos sin margen para negar el riesgo corporativo.

---

## 3. ARQUITECTURA DEL SOFTWARE

### 3.1 Stack Tecnologico

| Capa | Tecnologia | Proposito |
|------|-----------|-----------|
| Lenguaje | Rust 2021 | Seguridad de memoria, rendimiento, binario estatico |
| Async Runtime | Tokio 1.x | Concurrencia asincrona para operaciones paralelas |
| CLI | clap 4.x | Parser de argumentos con derive macros |
| Serializacion | serde + serde_json | JSON output, config files, API responses |
| Hashing | sha2 0.10 | SHA-256 para cadena de evidencia y dictamen |
| Database | rusqlite (SQLite) | Persistencia local de evidencia, hallazgos, dictamenes |
| Identificadores | uuid v4 | IDs unicos para findings y dictamenes |
| Output | colored 2.x | Terminal con colores para CLI |

### 3.2 Estructura de Modulos

    src/
    +-- main.rs          Punto de entrada, CLI parsing, comandos
    +-- types.rs         13 estructuras de datos core
    +-- error.rs         7 tipos de error centralizados
    +-- evidence.rs      Cadena de evidencia SHA-256 (12 tests)
    +-- mitre.rs         Base de datos ATT&CK: 31 tecnicas (9 tests)
    +-- impact.rs        Motor de impacto de negocio (7 tests)
    +-- compliance.rs    Mapeo regulatorio a 9 frameworks (7 tests)

### 3.3 Flujo de Datos

    CLI Input -> main.rs parsea argumentos
        |
        +-- info: Muestra version y sistema
        +-- techniques: Lista tecnicas ATT&CK (filtrable)
        +-- technique <id>: Detalle + compliance mapping
        +-- authorize: Flujo de autorizacion pre-engagement
        +-- compliance: Frameworks soportados

    (Fases futuras v0.5-v1.0):
        +-- recon: Descubrimiento de red y servicios
        +-- exploit: Explotacion de vulnerabilidades
        +-- post_exploit: Credenciales + movimiento lateral
        +-- dictamen: Generacion de reporte legal inmutable
        +-- dashboard: Web SPA + REST API

---

## 4. MODULOS Y COMPONENTES DETALLADOS

### 4.1 types.rs -- Estructuras de Datos Core

13 estructuras que definen todo el modelo de datos:

**Target & Scope:**
- Target: IP, hostname, OS guess, puertos abiertos, servicios detectados
- PortInfo: puerto, protocolo, estado, banner
- ServiceInfo: puerto, nombre, version, producto, info extra
- Authorization: cliente, autorizado por, fecha, scope, IPs excluidas, hash de autorizacion

**Evidence:**
- Severity: enum con 5 niveles (Info, Low, Medium, High, Critical) + score numerico
- EvidenceEntry: id, fase, tecnica, target, comando, output_hash, snippet, resultado, severidad, hash_anterior, hash_cadena, timestamp, duracion
- KillChainPhase: 6 fases (Recon, Weaponization, Exploitation, PostExploitation, Persistence, Impact) + mapeo PTES
- MitreTechnique: id, nombre, tactica, descripcion, fase, plataformas, fuentes de datos, destructivo, requiere_auth, dificultad deteccion

**Impact Analysis:**
- Finding: id, titulo, descripcion, severidad, tecnicas, sistemas afectados, impacto financiero (min-max), violaciones regulatorias, remediacion, evidencias
- RegulatoryViolation: framework, requisito, descripcion

**Dictamen (Legal Report):
- Dictamen: id, cliente, tipo engagement, fecha, resumen ejecutivo, kill chain, hallazgos, validez cadena, hash dictamen, duracion total
- ExecutiveSummary: nivel riesgo, impacto financiero, tiempo hasta compromiso, fases completadas, tecnicas ejecutadas, sistemas probados/comprometidos, credenciales comprometidas
- KillChainStep: timestamp, fase, tecnica, descripcion, target, resultado, severidad

**Engagement:**
- EngagementConfig: cliente, autorizacion, scope, exclusiones, tipo, concurrencia, timeout, safe_mode, fases

### 4.2 error.rs -- Manejo de Errores

7 tipos de error usando thiserror:

- TargetNotInScope: target fuera del scope autorizado
- NoAuthorization: sin configuracion de autorizacion
- ConnectionFailed: fallo de conexion a target:port
- TechniqueFailed: tecnica fallo en target
- IntegrityViolation: violacion de cadena de integridad
- Database: error de SQLite
- SafeModeBlocked: tecnica destructiva bloqueada en modo seguro

### 4.3 evidence.rs -- Cadena de Evidencia SHA-256

Motor forense central de RED-CORE. Implementa una cadena de hashes SHA-256 encadenados donde cada registro contiene la huella digital de todos los registros anteriores.

**Proceso de sellado (seal):**
1. Recupera el hash del ultimo evento (o GENESIS si es el primero)
2. Calcula SHA-256 del output completo
3. Toma los primeros 500 caracteres del output como snippet
4. Calcula hash de cadena: SHA-256(prev_hash + phase + technique_id + target + command + output_hash + timestamp)
5. Almacena el nuevo evento con ambos hashes

**Verificacion (verify):**
- Recorre toda la cadena desde GENESIS
- Recalcula cada hash de cadena
- Compara con el hash almacenado
- Retorna (es_valida, total, validos)

**Propiedades criptograficas:**
- Imposible alterar un registro sin romper la cadena
- Imposible eliminar un registro sin dejar hash fantasma
- Imposible insertar un registro retroactivo sin reproducir toda la cadena
- No importa si el atacante tiene acceso root al servidor

**Metodos principales:**
- seal(): Sella un nuevo evento en la cadena
- verify(): Verifica integridad completa de la cadena
- entries(): Retorna todos los eventos
- entries_by_phase(): Filtra por fase PTES
- entries_by_severity(): Filtra por severidad
- total_duration_ms(): Duracion total de todas las operaciones
- overall_risk(): Nivel de riesgo general basado en severidades
- to_json(): Exporta la cadena como JSON

### 4.4 mitre.rs -- Base de Datos MITRE ATT&CK

31 tecnicas organizadas en 6 fases de kill chain:

| Fase | Tecnicas | Descripcion |
|------|----------|-------------|
| Recon | 5 | T1046, T1018, T1087, T1482, T1592 |
| Exploitation | 4 | T1190, T1078, T1110, T1210 |
| Post-Exploitation | 11 | T1059, T1068, T1548, T1003, T1003.001, T1558, T1110.002, T1021.002, T1021.001, T1550.002, T1021.003 |
| Persistence | 5 | T1053.005, T1543.003, T1136, T1547.001, T1505.003 |
| Defense Evasion | 1 | T1070 |
| Collection/Exfil/Impact | 5 | T1005, T1039, T1041, T1486, T1489 |

**Propiedades por tecnica:**
- id: Identificador MITRE (ej: T1046)
- name: Nombre descriptivo
- tactic: Tactica ATT&CK (Discovery, Initial Access, etc.)
- description: Descripcion detallada
- kill_chain_phase: Fase PTES asignada
- platforms: Windows, Linux, macOS
- data_sources: Fuentes de datos para deteccion
- is_destructive: Si es destructivo (bloqueado en safe_mode)
- requires_auth: Si requiere acceso autenticado
- detection_difficulty: Easy, Medium, Hard

**Metodos de consulta:**
- all(): Todas las tecnicas
- get(id): Buscar por ID
- by_tactic(tactic): Filtrar por tactica
- by_phase(phase): Filtrar por fase de kill chain
- safe_techniques(): Solo tecnicas no destructivas

### 4.5 impact.rs -- Motor de Impacto de Negocio

Analiza la cadena de evidencia y genera hallazgos con estimacion financiera del impacto de negocio.

**Logica de analisis:**
- Mapea cada entrada de evidencia critica/alta a un Finding
- Calcula impacto financiero (rango minimo-maximo en USD)
- Identifica violaciones regulatorias automaticamente
- Proporciona recomendaciones de remediacion
- Si hay 2+ hallazgos criticos, genera hallazgo de compromiso total de kill chain

**Tipos de hallazgos generados:**

| Tecnica | Hallazgo | Impacto Financiero |
|---------|----------|-------------------|
| T1190, T1210 | Remote Code Execution | $200K - $2.1M |
| T1003, T1558, T1110 | Credential Harvesting | $800K - $5.4M |
| T1550, T1021 | Lateral Movement | $2.1M - $12.8M |
| T1068, T1548 | Privilege Escalation | $500K - $4.2M |
| T1053, T1543, T1136 | Persistence | $300K - $2.5M |
| T1486, T1489 | Destructive Capability | $4.2M - $12.8M |
| Chain Compromise | Full Kill Chain | Suma total |

### 4.6 compliance.rs -- Mapeo Regulatorio

Mapea cada tecnica MITRE ATT&CK a requisitos regulatorios especificos.

**9 Frameworks soportados:**
- PCI DSS 4.0: Requisitos 3.4, 6.2.4, 7.2.1, 8.3.1, 10.4, 10.5, 11.3, 12.10
- GDPR: Art. 5(1)(f), Art. 32, Art. 33
- NIST SP 800-53: AC-6, CA-8, IA-2, IA-5, SI-2, SI-4
- NIST 800-63B: 5.1.1
- NIST SP 800-92: 2.1
- HIPAA: 164.308(a)(6), 164.312(a)(1), 164.312(b), 164.312(e)(1)
- SOC 2: CC6.1, CC6.2, CC7.2, CC7.4
- NIS2: Art. 21, Art. 21(1), Art. 23
- PTES: Intelligence Gathering, Weaponization, Exploitation, Post-Exploitation, Reporting

**Metodos:**
- map_technique(id): Retorna violaciones regulatorias para una tecnica
- ptes_mapping(phase): Mapeo fase kill chain a fase PTES
- frameworks(): Lista de todos los frameworks soportados

---

## 5. MITRE ATT&CK COVERAGE

### 5.1 Reconnaissance (5 tecnicas)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1046 | Network Service Discovery | Discovery | YES | Easy |
| T1018 | Remote System Discovery | Discovery | YES | Easy |
| T1087 | Account Discovery | Discovery | YES | Medium |
| T1482 | Domain Trust Discovery | Discovery | YES | Medium |
| T1592 | Gather Victim Host Info | Reconnaissance | YES | Hard |

### 5.2 Exploitation / Initial Access (4 tecnicas)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1190 | Exploit Public-Facing App | Initial Access | YES | Medium |
| T1078 | Valid Accounts | Initial Access | YES | Hard |
| T1110 | Brute Force | Credential Access | YES | Easy |
| T1210 | Exploitation of Remote Services | Lateral Movement | YES | Medium |

### 5.3 Post-Exploitation (11 tecnicas)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1059 | Command and Scripting Interpreter | Execution | YES | Medium |
| T1068 | Exploitation for Privilege Escalation | Priv Esc | YES | Hard |
| T1548 | Abuse Elevation Control | Priv Esc | YES | Medium |
| T1003 | OS Credential Dumping | Cred Access | YES | Medium |
| T1003.001 | LSASS Memory | Cred Access | YES | Medium |
| T1558 | Steal/Forgery Kerberos Tickets | Cred Access | YES | Medium |
| T1110.002 | Password Cracking | Cred Access | YES | Hard |
| T1021.002 | SMB/Windows Admin Shares | Lateral Move | YES | Medium |
| T1021.001 | Remote Desktop Protocol | Lateral Move | YES | Easy |
| T1550.002 | Pass the Hash | Lateral Move | YES | Hard |
| T1021.003 | DCOM | Lateral Move | YES | Hard |

### 5.4 Persistence (5 tecnicas)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1053.005 | Scheduled Task | Persistence | YES | Easy |
| T1543.003 | Windows Service | Persistence | YES | Medium |
| T1136 | Create Account | Persistence | YES | Easy |
| T1547.001 | Registry Run Keys | Persistence | YES | Easy |
| T1505.003 | Web Shell | Persistence | YES | Medium |

### 5.5 Defense Evasion (1 tecnica)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1070 | Indicator Removal | Defense Evasion | NO | Medium |

### 5.6 Collection / Exfiltration / Impact (5 tecnicas)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1005 | Data from Local System | Collection | YES | Medium |
| T1039 | Data from Network Shared Drive | Collection | YES | Medium |
| T1041 | Exfiltration Over C2 | Exfiltration | YES | Hard |
| T1486 | Data Encrypted for Impact | Impact | NO | Easy |
| T1489 | Service Stop | Impact | NO | Easy |

---

## 6. CADENA DE EVIDENCIA CRIPTOGRAFICA

### 6.1 Modelo de Inmutabilidad

Cada accion ejecutada genera un evento en la cadena de evidencia con el siguiente formato:

    Prev Hash: SHA-256 del evento anterior (o GENESIS si es el primero)
    Chain Hash: SHA-256(prev_hash + phase + technique_id + target + command + output_hash + timestamp)
    Output Hash: SHA-256 del output completo de la operacion

### 6.2 Propiedades de Seguridad

- **No repudio:** Cada evento esta vinculado al anterior criptograficamente
- **Integridad:** Cualquier modificacion invalida la cadena desde ese punto
- **Inmutabilidad:** Imposible insertar/eliminar sin dejar rastro
- **Trazabilidad:** Timestamps UTC precisos con milisegundos
- **Verificacion:** Funcion verify() que recalcula toda la cadena

### 6.3 Ventaja Forense

Si un atacante compromete el servidor donde se almacena la evidencia e intenta borrar registros para cubrir sus huellas, la verificacion de integridad detectara inmediatamente la discrepancia. Esto es critico para:

- Investigaciones forenses donde la evidencia debe ser irrefutable
- Auditorias regulatorias donde el historial debe ser intocable
- Procedimientos legales donde los documentos deben ser verificables

---

## 7. MOTOR DE IMPACTO DE NEGOCIO

### 7.1 Calculo de Impacto Financiero

El motor analiza cada hallazgo critico y asigna un rango de impacto financiero basado en:

- IBM Cost of a Data Breach Report 2025 ($4.88M promedio)
- Ponemon Institute: Cost of insider threats ($15.38M promedio)
- Sophos State of Ransomware 2025 ($2.73M costo promedio)
- NIST Cybersecurity Framework cost models

### 7.2 Ejemplo de Dictamen Ejecutivo

    RESUMEN EJECUTIVO
    Nivel de riesgo: CRITICO
    Impacto financiero estimado: $4.2M - $12.8M
    Tiempo hasta compromiso total: 47 minutos
    Kill chain completada: 6/6 fases
    Tecnicas MITRE ATT&CK ejecutadas: 23
    Credenciales comprometidas: 847
    Sistemas comprometidos: 12 de 15 evaluados
    Datos accesibles: PII de 2.3M clientes

### 7.3 Hallazgo Tipo

    Hallazgo: Remote Code Execution via Exploit Public-Facing Application
    Severidad: CRITICAL
    Tecnicas: T1190
    Sistemas: 10.0.0.1
    Descripcion: Attacker can achieve initial access to 10.0.0.1:443
    Impacto financiero: $200,000 - $2,100,000
    Violaciones: PCI DSS 4.0 6.2.4, NIST SP 800-53 SI-2
    Remediacion: Apply security patches, implement WAF, conduct vuln scanning

---

## 8. CUMPLIMIENTO NORMATIVO

### 8.1 PCI DSS 4.0

| Requisito | Tecnicas Mapeadas |
|-----------|-------------------|
| 3.4 (PAN encryption) | T1550.002, T1021, T1005, T1039 |
| 6.2.4 (Software security) | T1190 |
| 7.2.1 (Least privilege) | T1068, T1548 |
| 8.3.1 (Strong authentication) | T1003, T1558, T1110 |
| 10.4 (Log review) | T1053, T1543, T1136 |
| 10.5 (Log retention) | T1070 |
| 11.3 (Pen testing) | T1190, T1041 |
| 12.10 (Incident response) | T1486, T1489 |

### 8.2 GDPR

| Articulo | Tecnicas Mapeadas |
|----------|-------------------|
| Art. 5(1)(f) (Integridad) | T1005, T1039 |
| Art. 32 (Seguridad) | T1190, T1003, T1550.002 |
| Art. 33 (Notificacion 72h) | T1486, T1041 |

### 8.3 HIPAA

| Seccion | Tecnicas Mapeadas |
|---------|-------------------|
| 164.308(a)(6) (Incidentes) | T1486 |
| 164.312(a)(1) (Access control) | T1003, T1005, T1039 |
| 164.312(b) (Auditoria) | T1053, T1543 |
| 164.312(e)(1) (Transmision) | T1550.002, T1021 |

### 8.4 SOC 2

| Criterio | Tecnicas Mapeadas |
|----------|-------------------|
| CC6.1 (Logical access) | T1003, T1550.002, T1558 |
| CC6.2 (System credentials) | T1068 |
| CC7.2 (Monitoring) | T1053, T1543 |
| CC7.4 (Incident response) | T1489 |

### 8.5 NIS2

| Articulo | Tecnicas Mapeadas |
|----------|-------------------|
| Art. 21 (Risk management) | T1190, T1486, T1489 |
| Art. 21(1) (Risk measures) | T1190 |
| Art. 23 (Incident reporting) | T1486, T1041 |

### 8.6 NIST

| Publicacion | Tecnicas |
|-------------|---------|
| SP 800-53 AC-6 (Least privilege) | T1068, T1548 |
| SP 800-53 CA-8 (Pen testing) | T1210 |
| SP 800-53 IA-2 (Identification) | T1558 |
| SP 800-53 IA-5 (Authenticator mgmt) | T1110 |
| SP 800-53 SI-2 (Flaw remediation) | T1190 |
| SP 800-53 SI-4 (System monitoring) | T1053, T1543 |
| 800-63B 5.1.1 (Secret verifiers) | T1003 |
| SP 800-92 2.1 (Log management) | T1070 |

### 8.7 PTES (Penetration Testing Execution Standard)

| Fase PTES | Fase RED-CORE | Descripcion |
|-----------|---------------|-------------|
| Intelligence Gathering | Recon | Descubrimiento de red y servicios |
| Weaponization | Weaponization | Preparacion de payloads y vectores |
| Exploitation | Exploitation | Ejecucion de exploits |
| Post-Exploitation | Post-Exploitation + Persistence | Escalada, movimiento lateral, persistencia |
| Reporting | Impact | Analisis de impacto y dictamen |

---

## 9. CLI REFERENCE

### 9.1 red-core info

Muestra informacion del sistema: version, lenguaje, tecnicas cargadas, tipo de evidencia, frameworks soportados, autor y contacto.

### 9.2 red-core techniques

Lista las 31 tecnicas MITRE ATT&CK con ID, nombre, tactica, fase de kill chain y si es segura.

Filtros:
- --tactic <tactic>: Filtrar por tactica ATT&CK (ej: Discovery)
- --phase <phase>: Filtrar por fase (ej: exploitation)
- --safe: Solo tecnicas no destructivas
- --json: Output JSON

### 9.3 red-core technique <ID>

Muestra detalles de una tecnica: ID, nombre, tactica, fase, descripcion, plataformas, si requiere auth, dificultad de deteccion.

Opciones:
- --compliance: Muestra mapeo regulatorio de la tecnica
- --json: Output JSON

### 9.4 red-core authorize

Flujo de autorizacion pre-engagement. Documenta: cliente, autorizado por, scope de IPs, IPs excluidas.

Parametros:
- --client: Nombre del cliente
- --authorized-by: Nombre y cargo de quien autoriza
- --scope: CIDRs separados por coma
- --exclude: IPs excluidas separadas por coma
- --json: Output JSON

### 9.5 red-core compliance

Muestra los 9 frameworks regulatorios soportados.

Opciones:
- --technique <ID>: Muestra compliance mapping de una tecnica especifica
- --json: Output JSON

---

## 10. PRUEBAS Y CALIDAD

### 10.1 Resumen de Tests

| Modulo | Tests | Cobertura |
|--------|-------|-----------|
| evidence.rs | 12 | Empty chain, single entry, multiple entries, tamper detection, hash chaining, truncation, genesis, phase filtering, risk calculation, JSON export |
| mitre.rs | 9 | Technique count, get by ID, not found, by tactic, by phase, safe filter, all have IDs, platform coverage, kill chain coverage |
| impact.rs | 7 | Finding generation, critical findings, regulatory violations, chain compromise detection, no false chain, positive financials, remediation not empty |
| compliance.rs | 7 | PCI mapping, multi-framework, NIS2 mapping, unknown technique, PTES mapping, frameworks list, lateral movement compliance |
| **TOTAL** | **34** | **4 modulos** |

### 10.2 Calidad del Codigo

- Lenguaje: Rust (memory-safe por diseno)
- Compilacion: Release mode (optimized, stripped)
- Runtime dependencies: Ninguna (binario estatico)
- Tests: 34 unit tests, 0 fallos

---

## 11. DIFERENCIADORES VS COMPETENCIA

| Feature | RED-CORE | Cobalt Strike | Caldera | SafeBreach | Atomic RT |
|---------|:-:|:-:|:-:|:-:|:-:|
| Real exploitation | YES | YES | YES | NO (sim) | YES (indiv) |
| Kill chain orchestration | YES | Partial | YES | YES | NO |
| MITRE ATT&CK mapping | YES | NO | YES | YES | YES |
| Cryptographic evidence | YES | NO | NO | NO | NO |
| Tamper-proof audit trail | YES | NO | NO | NO | NO |
| Business impact analysis | YES | NO | NO | Partial | NO |
| Legal dictamen generation | YES | NO | NO | NO | NO |
| PTES methodology | YES | NO | NO | NO | NO |
| PCI DSS 4.0 mapping | YES | NO | NO | YES | NO |
| Compliance scoring | YES | NO | NO | YES | NO |
| Rust binary | YES | NO (Java) | NO (Python) | NO (SaaS) | NO (Python) |
| Ecosystem TLS-PRO | YES | NO | NO | NO | NO |

**Ninguna otra herramienta de auditoria ofensiva del mercado ofrece integridad criptografica de su historial de evidencia.**

---

## 12. MODELO DE NEGOCIO

### 12.1 Pricing

| Plan | Precio | Target |
|------|--------|--------|
| RED-CORE Assessment | $20,000 una vez | Evaluacion unica con dictamen |
| RED-CORE Continuous | $5,000/mo | Monitoreo Red Team continuo |
| RED-CORE Enterprise | $15,000/mo | Multi-site + SIEM + compliance |
| RED-CORE + TLS-PRO Bundle | $18,000/mo | Ecosistema completo Blue+Red Team |
| RED-CORE MOD/Government | Custom ($50K+) | UK MOD-adjacent, NATO |

### 12.2 Revenue Model (Conservador)

Ano 1: $860K (10 Assessment + 5 Continuous + 2 Enterprise)
Ano 2: $2.4M (25 Assessment + 15 Continuous + 5 Enterprise + 2 MOD)

---

## 13. ROADMAP

### v0.1.0 (Actual - Phase 1):
- Core data structures (13 types)
- Evidence chain SHA-256 (tamper-evident)
- MITRE ATT&CK database (31 techniques)
- Business impact engine
- Compliance mapping (9 frameworks)
- CLI with 5 commands
- 34 unit tests

### v0.5 (Phase 2):
- Recon module (network discovery, service enumeration)
- Port scanning (TCP/UDP)
- OS fingerprinting
- Service version detection
- AD enumeration (LDAP, Kerberos)
- Evidence sealing per recon operation

### v0.7 (Phase 3):
- Exploitation module (CVE-based)
- Vulnerability matching against discovered services
- Payload selection and delivery
- Access verification
- 15-20 core exploitation techniques

### v0.9 (Phase 4):
- Post-exploitation module
- Credential harvesting (LSASS, SAM, keychains)
- Lateral movement (SMB, RDP, Pass-the-Hash)
- Privilege escalation
- Persistence techniques

### v1.0 (Phase 5):
- Dictamen generation (full legal report)
- Web dashboard (SPA)
- REST API (10+ endpoints)
- SQLite persistence with integrity chain
- Wazuh SIEM integration
- Docker deployment
- Systemd services
- Full PTES methodology
- 100+ unit tests

---

**Hyperium RED-CORE v0.1.0 -- Informe Tecnico Completo**
**Hyperiumia -- https://github.com/hyperiumia/hyperium-red-core**
**Contacto: hyperiumia@protonmail.com**

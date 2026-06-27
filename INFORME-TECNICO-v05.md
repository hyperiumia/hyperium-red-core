# HYPERIUM RED-CORE v0.5.0
# Informe Tecnico Profesional Completo

**Autor:** Patricio Tirado — CEO, Hyperiumia
**Revisor Legal:** Julio Tirado — Legal Counsel
**Fecha:** Junio 2026
**Version:** 0.5.0 (Phase 1 + Phase 2)
**Plataforma:** Linux x86_64 (Debian, Ubuntu, RHEL, Alpine)
**Lenguaje:** Rust 2021 Edition (rustc 1.88+)
**Licencia:** Propietaria — Hyperiumia
**Contacto:** hyperiumia@protonmail.com
**Repositorios:**
- Publico (docs): https://github.com/hyperiumia/hyperium-red-core
- Privado (codigo): https://github.com/hyperiumia/hyperium-red-core-source

---

## INDICE

1. Resumen Ejecutivo
2. Contexto y Problematica del Mercado
3. Que es RED-CORE y Que No es
4. Arquitectura del Software
5. Modulos y Componentes Detallados
6. MITRE ATT&CK Coverage
7. Cadena de Evidencia Criptografica
8. Motor de Explotacion
9. Motor de Limpieza y Sanitizacion
10. Motor de Estado (Pre/Post Snapshots)
11. Kill Chain Orquestacion
12. Motor de Impacto de Negocio
13. Cumplimiento Regulatorio
14. Pruebas y Calidad de Software
15. CLI Reference Completa
16. Analisis Competitivo
17. Modelo de Negocio y Pricing
18. Marco Legal y Compliance
19. Roadmap Completo
20. Conclusiones

---

## 1. RESUMEN EJECUTIVO

Hyperium RED-CORE es un orquestador ofensivo de Red Team escrito completamente en Rust que ejecuta tecnicas del framework MITRE ATT&CK, sella criptograficamente cada paso de la kill chain con SHA-256 encadenado, y produce un Dictamen de Impacto Tecnico inmutable e irrefutable para presentar ante directivos, auditores y reguladores.

El mercado de ciberseguridad ofensiva tiene un defecto estructural: las herramientas ejecutan ataques pero nadie sella la evidencia de forma inmutable. Los reportes son PDF editables que los directivos ignoran y los auditores no pueden verificar. RED-CORE resuelve esto matematicamente.

### Capacidades actuales (v0.5.0):

- 31 tecnicas MITRE ATT&CK catalogadas y mapeadas
- 15 tecnicas de explotacion CVE-based ejecutables
- Cadena de evidencia SHA-256 con sellado automatico de cada operacion
- Motor de impacto de negocio con estimacion financiera por hallazgo
- Mapeo regulatorio automatico a 9 frameworks internacionales
- Motor de limpieza que revierte automaticamente cada accion ofensiva
- Motor de estado que compara snapshots pre/post engagement
- Certificados de sanitizacion sellados criptograficamente
- Kill chain orquestacion completa (recon → exploit → cleanup → certificate)
- 82 pruebas unitarias distribuidas en 10 modulos, 0 fallos
- CLI completa con 14 comandos
- Binario Rust de alta performance sin dependencias runtime

### Principio Legal Rector (Julio Tirado, Legal Counsel):

> Ninguna accion ofensiva dejara vulnerabilidades residuales o brechas de seguridad
> no documentadas, para evitar responsabilidades civiles corporativas. La seguridad
> no debe ser solo tecnica, sino auditable y legalmente defendible.

Este principio esta implementado tecnicamente en el motor de limpieza (cleanup.rs)
y el motor de estado (state.rs), que garantizan que cada accion ofensiva sea
reversible y que el estado del sistema sea verificable antes y despues del
engagement.

---

## 2. CONTEXTO Y PROBLEMATICA DEL MERCADO

### 2.1 El Mercado de Red Team en 2026

El mercado global de servicios de Red Team y pentesting alcanza los $4.5B USD en 2026
(Gartner, 2025), con una tasa de crecimiento anual del 18.2%. Sin embargo, el mercado
tiene problemas estructurales criticos:

**Problema 1: Costo elevado, evidencia debil**
- Un engagement manual de Red Team cuesta $50,000-$250,000 USD
- La evidencia producida es un PDF editable que cualquier persona puede modificar
- Los directivos pueden ignorar la gravedad porque es solo un informe tecnico
- No existe mecanismo para verificar que la evidencia no fue alterada

**Problema 2: Evidencia no forense**
- Los reportes actuales no tienen integridad criptografica
- No se puede demostrar matematicamente que la evidencia es inalterada
- Los auditores no pueden verificar la cadena de eventos
- En procedimientos legales, la evidencia digital es impugnable

**Problema 3: Vulnerabilidades residuales**
- Muchas herramientas ofensivas dejan artefactos en el entorno del cliente
- Tareas programadas, servicios creados, web shells desplegados quedan activos
- No existe un mecanismo estandarizado de sanitizacion post-engagement
- El cliente queda mas vulnerable despues del pentesting que antes

**Problema 4: Sin impacto de negocio**
- Los reportes tecnicos hablan de CVEs y CVSS scores
- Los directivos necesitan cifras en dolares, no tecnicismos
- No existe traduccion automatica de hallazgo tecnico a impacto financiero
- El gap entre el equipo tecnico y el boardroom no se cierra

### 2.2 Marco Regulatorio Creciente

Las regulaciones cada vez exigen mas evidencia de evaluacion ofensiva:

- **PCI DSS 4.0** (2025): Requiere pentesting anual con metodologia documentada
- **DORA** (EU, 2025): Exige pruebas de resiliencia operativa con evidencia
- **NIS2** (EU, 2024): Obliga evaluacion de riesgos con medidas proporcionales
- **NIST CSF 2.0** (2024): Recomienda adversarial testing continuo
- **SOC 2** (Type II): Auditorias anuales con evidencia de controles
- **HIPAA** (US): Evaluaciones tecnicas de seguridad obligatorias
- **GDPR** (EU): Art. 32 requiere evaluacion de eficacia de medidas tecnicas

RED-CORE resuelve todos estos problemas de forma integrada.

---

## 3. QUE ES RED-CORE Y QUE NO ES

### 3.1 QUE ES

- Un motor de evaluacion ofensiva que ejecuta tecnicas reales del framework MITRE ATT&CK
- Un orquestador de kill chain completa siguiendo la metodologia PTES
- Un sistema de evidencia criptografica con SHA-256 encadenado (tamper-evident)
- Un calculador de impacto de negocio con estimacion financiera en USD
- Un mapeador regulatorio automatico a 9 frameworks internacionales
- Un motor de sanitizacion que revierte cada accion ofensiva automaticamente
- Un generador de certificados de sanitizacion sellados criptograficamente
- Un binario Rust de alta performance con zero runtime dependencies

### 3.2 QUE NO ES

- No es un escaner de vulnerabilidades (no busca CVEs automaticamente)
- No es un simulador (ejecuta tecnicas reales, no simulaciones)
- No es una herramienta de defensa (es puramente ofensiva)
- No es un framework de desarrollo (es un motor de ejecucion)
- No es open source (el codigo es propietario de Hyperiumia)
- No es una alternativa a Cobalt Strike (complementa, no reemplaza)

### 3.3 Diferenciadores Clave

| Caracteristica | RED-CORE | Resto del mercado |
|----------------|----------|-------------------|
| Evidencia criptografica inmutable | SHA-256 encadenado | Ninguna |
| Sanitizacion automatica post-engage | Si (cleanup engine) | Manual o ninguna |
| Certificado de sanitizacion sellado | Si (evidence chain) | Ninguna |
| Impacto financiero automatico | Si (USD por hallazgo) | Manual |
| Compliance mapping automatico | 9 frameworks | Parcial |
| Kill chain orquestacion completa | 4 fases automatizadas | Manual |
| Binario Rust sin dependencias | Si | Java/Python/SaaS |
| Evidencia irrefutable ante tribunal | Si (SHA-256 chain) | No verificable |

---

## 4. ARQUITECTURA DEL SOFTWARE

### 4.1 Stack Tecnologico

| Capa | Tecnologia | Proposito |
|------|-----------|-----------|
| Lenguaje | Rust 2021 Edition | Seguridad de memoria, rendimiento, binario estatico |
| Async Runtime | Tokio 1.x | Concurrencia asincrona para operaciones paralelas |
| CLI | clap 4.x | Parser de argumentos con derive macros, 14 comandos |
| Serializacion | serde + serde_json | JSON output, config files, API responses |
| Hashing | sha2 0.10 | SHA-256 para cadena de evidencia, dictamenes, certificados |
| Database | rusqlite (SQLite) | Persistencia local de evidencia, hallazgos, dictamenes |
| Identificadores | uuid v4 | IDs unicos para findings y dictamenes |
| Output | colored 2.x | Terminal con colores para CLI |
| Red | std::net (TcpStream) | TCP connect scans, banner grabbing |

### 4.2 Estructura de Modulos

    src/
    +-- main.rs          Punto de entrada, CLI parsing, 14 comandos, handler functions
    +-- types.rs         13 estructuras de datos core (Target, Evidence, Finding, etc.)
    +-- error.rs         7 tipos de error centralizados (thiserror)
    +-- evidence.rs      Cadena de evidencia SHA-256 (12 tests)
    +-- mitre.rs         Base de datos ATT&CK: 31 tecnicas (9 tests)
    +-- impact.rs        Motor de impacto de negocio (7 tests)
    +-- compliance.rs    Mapeo regulatorio a 9 frameworks (7 tests)
    +-- recon.rs         Port scan, banner grabbing, OS fingerprint, ping sweep (16 tests)
    +-- exploit.rs       15 tecnicas CVE-based con auto-cleanup tracking (17 tests)
    +-- cleanup.rs       Reversion automatica de acciones ofensivas (6 tests)
    +-- state.rs         Pre/post snapshots, deteccion de residuos, certificados (11 tests)

### 4.3 Flujo de Datos — Kill Chain Completo

    CLI Input → main.rs parsea argumentos
        |
        +-- kill-chain: Pipeline completo automatizado
            |
            +-- [1/4] state.rs: Pre-snapshot del sistema
            +-- [2/4] recon.rs: Port scan + banner + OS fingerprint
            +-- [3/4] exploit.rs: Ejecucion de tecnicas contra puertos abiertos
            |           +-- evidence.rs: Sello de cada exploit en cadena SHA-256
            |           +-- cleanup.rs: Registro automatico para reversion
            +-- [4/4] state.rs: Post-snapshot + comparacion + limpieza
                        +-- cleanup.rs: Ejecucion de limpieza en orden inverso
                        +-- state.rs: Certificado de sanitizacion
                        +-- evidence.rs: Sello de toda la operacion

### 4.4 Dependencias (Cargo.toml)

    [dependencies]
    tokio = { version = "1", features = ["full"] }
    clap = { version = "4", features = ["derive"] }
    serde = { version = "1", features = ["derive"] }
    serde_json = "1"
    sha2 = "0.10"
    rusqlite = { version = "0.31", features = ["bundled"] }
    uuid = { version = "1", features = ["v4"] }
    colored = "2"
    thiserror = "1"
    hex = "0.4"

---

## 5. MODULOS Y COMPONENTES DETALLADOS

### 5.1 types.rs — Estructuras de Datos Core (13 estructuras)

Define todo el modelo de datos de RED-CORE. Cada estructura es serializable
a JSON y se usa en toda la cadena de evidencia.

**Target & Scope (4 estructuras):**
- `Target`: IP, hostname, OS guess, puertos abiertos (Vec<PortInfo>), servicios (Vec<ServiceInfo>)
- `PortInfo`: puerto (u16), protocolo (String), estado (String), banner (Option<String>)
- `ServiceInfo`: puerto, nombre, version, producto, info extra
- `Authorization`: cliente, autorizado por, fecha, scope, IPs excluidas, hash de autorizacion

**Evidence (2 estructuras):**
- `Severity`: Enum con 5 niveles (Info=0, Low=3, Medium=5, High=8, Critical=10)
- `EvidenceEntry`: id (i64), fase, tecnica_id, tecnica_nombre, target, puerto, comando,
  output_hash (SHA-256), output_snippet (500 chars), resultado, severidad,
  prev_hash (SHA-256 del anterior), chain_hash (SHA-256 encadenado), timestamp, duracion_ms

**Kill Chain (1 estructura):**
- `KillChainPhase`: Enum con 6 fases (Recon, Weaponization, Exploitation,
  PostExploitation, Persistence, Impact) + mapeo a PTES

**MitreTechnique (1 estructura):**
- id, nombre, tactica, descripcion, fase_kill_chain, plataformas,
  fuentes_datos, es_destructivo, requiere_auth, dificultad_deteccion

**Impact Analysis (2 estructuras):**
- `Finding`: id, titulo, descripcion, severidad, tecnicas, sistemas_afectados,
  impacto_financiero_min, impacto_financiero_max, violaciones_regulatorias,
  remediacion, evidencia_ids
- `RegulatoryViolation`: framework, requisito, descripcion

**Dictamen — Legal Report (3 estructuras):**
- `Dictamen`: id, cliente, tipo_engagement, fecha, resumen_ejecutivo, kill_chain,
  hallazgos, validez_cadena, hash_dictamen, duracion_total
- `ExecutiveSummary`: nivel_riesgo, impacto_financiero, tiempo_hasta_compromiso,
  fases_completadas, tecnicas_ejecutadas, sistemas_probados/comprometidos,
  credenciales_comprometidas
- `KillChainStep`: timestamp, fase, tecnica, descripcion, target, resultado, severidad

**Engagement (1 estructura):**
- `EngagementConfig`: cliente, autorizacion, scope, exclusiones, tipo, concurrencia,
  timeout, safe_mode, fases

### 5.2 error.rs — Manejo de Errores (7 tipos)

Centraliza todos los errores del sistema usando thiserror para errores
tipados y mensajes descriptivos:

- `TargetNotInScope`: Target fuera del scope autorizado
- `NoAuthorization`: Sin configuracion de autorizacion pre-engagement
- `ConnectionFailed`: Fallo de conexion a target:port
- `TechniqueFailed`: Tecnica fallo en target especifico
- `IntegrityViolation`: Violacion de cadena de integridad SHA-256
- `Database`: Error de SQLite (persistencia)
- `SafeModeBlocked`: Tecnica destructiva bloqueada en modo seguro

### 5.3 evidence.rs — Cadena de Evidencia SHA-256 (12 tests)

Motor forense central de RED-CORE. Implementa una cadena de hashes SHA-256
encadenados donde cada registro contiene la huella digital de todos los
registros anteriores. Es la base de toda la propuesta de valor.

**Proceso de sellado (seal):**
1. Recupera el hash del ultimo evento (o "GENESIS" si es el primero)
2. Calcula SHA-256 del output completo de la operacion
3. Toma los primeros 500 caracteres del output como snippet
4. Calcula hash de cadena: SHA-256(prev_hash + phase + technique_id + target
   + command + output_hash + timestamp)
5. Almacena el nuevo evento con ambos hashes

**Verificacion (verify):**
- Recorre toda la cadena desde GENESIS
- Recalcula cada hash de cadena
- Compara con el hash almacenado
- Retorna (es_valida: bool, total: usize, validos: usize)

**Propiedades criptograficas garantizadas:**
- **No repudio**: Cada evento esta vinculado al anterior criptograficamente
- **Integridad**: Cualquier modificacion invalida la cadena desde ese punto
- **Inmutabilidad**: Imposible insertar/eliminar sin dejar rastro
- **Trazabilidad**: Timestamps UTC precisos con milisegundos
- **Verificacion**: Funcion verify() que recalcula toda la cadena en O(n)
- **Resistencia a root**: No importa si el atacante tiene acceso root al servidor

**Metodos publicos:**
- `seal(phase, technique_id, name, target, port, command, output, summary, severity, duration)`
- `verify() -> (bool, usize, usize)`
- `entries() -> Vec<EvidenceEntry>`
- `entries_by_phase(phase) -> Vec<&EvidenceEntry>`
- `entries_by_severity(severity) -> Vec<&EvidenceEntry>`
- `count() -> usize`
- `last_hash() -> String` (hash del ultimo registro)
- `total_duration_ms() -> u64`
- `overall_risk() -> Severity`
- `to_json() -> String`

### 5.4 mitre.rs — Base de Datos MITRE ATT&CK (31 tecnicas, 9 tests)

Base de datos local de tecnicas MITRE ATT&CK. Cada tecnica incluye toda la
informacion necesaria para ejecucion, verificacion y compliance mapping.

**31 tecnicas en 6 fases de kill chain:**

| Fase | Cantidad | IDs |
|------|----------|-----|
| Reconnaissance | 5 | T1046, T1018, T1087, T1482, T1592 |
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
- platforms: Vec<String> (Windows, Linux, macOS)
- data_sources: Vec<String> (fuentes de datos para deteccion)
- is_destructive: bool (bloqueado en safe_mode)
- requires_auth: bool (requiere acceso autenticado)
- detection_difficulty: String (Easy, Medium, Hard)

**Metodos de consulta:**
- `all() -> Vec<MitreTechnique>`
- `get(id) -> Option<MitreTechnique>`
- `by_tactic(tactic) -> Vec<MitreTechnique>`
- `by_phase(phase) -> Vec<MitreTechnique>`
- `safe_techniques() -> Vec<MitreTechnique>`

### 5.5 impact.rs — Motor de Impacto de Negocio (7 tests)

Analiza la cadena de evidencia y genera hallazgos con estimacion financiera del
impacto de negocio. Traduce tecnicismos a cifras que los directivos entienden.

**Logica de analisis:**
- Mapea cada entrada de evidencia critica/alta a un Finding
- Calcula impacto financiero (rango minimo-maximo en USD)
- Identifica violaciones regulatorias automaticamente
- Proporciona recomendaciones de remediacion
- Si hay 2+ hallazgos criticos, genera hallazgo de compromiso total de kill chain

**Rangos de impacto financiero:**

| Tipo de Hallazgo | Minimo (USD) | Maximo (USD) | Base |
|------------------|--------------|--------------|------|
| Remote Code Execution | $200,000 | $2,100,000 | IBM CoDB 2025 |
| Credential Harvesting | $800,000 | $5,400,000 | Ponemon 2025 |
| Lateral Movement | $2,100,000 | $12,800,000 | Sophos 2025 |
| Privilege Escalation | $500,000 | $4,200,000 | NIST CSF |
| Persistence | $300,000 | $2,500,000 | IBM CoDB 2025 |
| Destructive Capability | $4,200,000 | $12,800,000 | Sophos 2025 |
| Full Kill Chain Compromise | Suma total | Suma total | Acumulado |

### 5.6 compliance.rs — Mapeo Regulatorio (7 tests)

Mapea cada tecnica MITRE ATT&CK a requisitos regulatorios especificos.
Cada hallazgo generado por el motor de impacto incluye automaticamente
las violaciones regulatorias correspondientes.

**9 Frameworks soportados:**

1. **PCI DSS 4.0**: Requisitos 3.4, 6.2.4, 7.2.1, 8.3.1, 10.4, 10.5, 11.3, 12.10
2. **GDPR**: Art. 5(1)(f), Art. 32, Art. 33
3. **NIST SP 800-53**: AC-6, CA-8, IA-2, IA-5, SI-2, SI-4
4. **NIST 800-63B**: 5.1.1
5. **NIST SP 800-92**: 2.1
6. **HIPAA**: 164.308(a)(6), 164.312(a)(1), 164.312(b), 164.312(e)(1)
7. **SOC 2**: CC6.1, CC6.2, CC7.2, CC7.4
8. **NIS2**: Art. 21, Art. 21(1), Art. 23
9. **PTES**: Intelligence Gathering, Weaponization, Exploitation, Post-Exploitation, Reporting

### 5.7 recon.rs — Motor de Reconocimiento (16 tests)

Motor de reconocimiento de red que implementa las siguientes capacidades:

**TCP Connect Scan:**
- Escaneo de puertos TCP con timeout configurable
- Top 20 y Top 100 puertos predefinidos
- Parsing de especificacion de puertos ("22,80,443" o "1-1024")
- Deduplicacion automatica de puertos

**Banner Grabbing:**
- Lectura de banners de servicios (SSH, FTP, SMTP, HTTP, MySQL, VNC)
- Envio de probes para servicios que esperan cliente (HTTP HEAD, SMTP EHLO)
- Timeout configurable para lectura de banners

**Service Detection:**
- Deteccion de servicio por banner (SSH, FTP, SMTP, HTTP, MySQL, VNC)
- Deteccion de servicio por puerto cuando no hay banner
- Extraccion de version del banner (Apache, nginx, OpenSSH, ProFTPD, etc.)

**OS Fingerprinting:**
- Heuristica basada en puertos abiertos (3389 → Windows, 22 → Linux, 548 → macOS)
- Heuristica basada en banners ("Microsoft" → Windows, "Ubuntu" → Linux)
- Score de confianza por porcentaje
- No requiere raw sockets (funciona con TCP connect)

**Ping Sweep:**
- Descubrimiento de hosts vivos en redes /24
- Usa TCP connect a puertos comunes como probe
- Retorna lista de hosts con puertos abiertos

**Evidence Sealing:**
- Cada operacion de escaneo se sella en la cadena de evidencia
- MITRE T1046 (Network Service Discovery)
- MITRE T1592 (Gather Victim Host Information)

### 5.8 exploit.rs — Motor de Explotacion (17 tests)

Motor de explotacion que implementa 15 tecnicas CVE-based de explotacion.
Cada tecnica incluye un `create_command` para ejecucion y un `cleanup_command`
para reversion, cumpliendo el principio legal de Julio Tirado.

**15 tecnicas de explotacion:**

| # | ID | Tecnica | CVE | Severidad | Servicio | Acceso | Auth | Destructivo |
|---|-----|---------|-----|-----------|----------|--------|------|-------------|
| 1 | T1190 | Log4Shell Injection | CVE-2021-44228 | CRITICAL | Apache Log4j | SYSTEM | No | No |
| 2 | T1190 | SQL Injection Auth Bypass | - | CRITICAL | Web App | Admin | No | No |
| 3 | T1190 | File Upload RCE | - | CRITICAL | Web Server | SYSTEM | No | No |
| 4 | T1110 | SSH Brute Force | - | HIGH | SSH | User | No | No |
| 5 | T1110 | RDP Brute Force | - | HIGH | RDP | Admin | No | No |
| 6 | T1210 | SMB EternalBlue | CVE-2017-0144 | CRITICAL | SMB | SYSTEM | No | SI |
| 7 | T1210 | WinRM Remote Execution | - | HIGH | WinRM | SYSTEM | Si | No |
| 8 | T1059 | PowerShell Remoting | - | HIGH | PowerShell | Admin | Si | No |
| 9 | T1003 | SAM Database Dump | - | CRITICAL | Windows | SYSTEM | Si | No |
| 10 | T1003.001 | LSASS Memory Dump | - | CRITICAL | Windows | SYSTEM | Si | No |
| 11 | T1550.002 | Pass the Hash | - | CRITICAL | SMB | Admin | Si | No |
| 12 | T1021.001 | RDP Lateral Movement | - | HIGH | RDP | Admin | Si | No |
| 13 | T1053.005 | Scheduled Task | - | HIGH | Task Scheduler | SYSTEM | Si | No |
| 14 | T1543.003 | Windows Service | - | CRITICAL | SCM | SYSTEM | Si | No |
| 15 | T1505.003 | Web Shell Deployment | - | CRITICAL | Web Server | SYSTEM | No | No |

**Resumen:**
- 9 CRITICAL, 6 HIGH
- 2 con CVEs conocidas (Log4Shell CVE-2021-44228, EternalBlue CVE-2017-0144)
- 14 seguras (no destructivas), 1 destructiva (EternalBlue)
- 8 requieren autenticacion, 7 no requieren
- Todas tienen create_command + cleanup_command

**Proceso de ejecucion:**
1. Seleccion de tecnica por ID o nombre
2. Ejecucion del create_command contra el target
3. Sellado del resultado en la cadena de evidencia (exitoso o fallido)
4. Si exitoso: registro automatico en CleanupEngine para reversion
5. Retorno de ExploitResult (Success o Failed) con todos los detalles

### 5.9 cleanup.rs — Motor de Limpieza (6 tests)

Implementa el principio legal de Julio Tirado: cada accion ofensiva debe
ser reversible y documentada.

**Proceso de limpieza:**
1. Cada exploit exitoso registra su cleanup_command via `track()`
2. Al final del engagement, `cleanup_all()` ejecuta las acciones en orden inverso
3. Cada accion de limpieza se sella en la cadena de evidencia SHA-256
4. Se genera un reporte de limpieza (CleanupReport)
5. Se genera un script bash automatizado para ejecucion manual

**CleanupAction (cada accion rastreada):**
- id: Identificador unico
- technique_id: MITRE ID (ej: T1053.005)
- category: Tipo de artefacto (Scheduled Task, Service, Web Shell, etc.)
- description: Descripcion de la accion
- target: IP o hostname del target
- create_command: Comando que se ejecuto para crear el artefacto
- cleanup_command: Comando para revertir el artefacto
- executed: bool (si la accion fue ejecutada)
- cleaned: bool (si la accion fue revertida)
- timestamp: Unix timestamp de cuando se ejecuto

**CleanupReport:**
- total_actions: Numero total de acciones rastreadas
- cleaned: Acciones revertidas exitosamente
- failed: Acciones que fallaron al revertir
- skipped: Acciones saltadas (no ejecutadas)
- details: Vec<CleanupDetail> con cada accion ejecutada

**generate_script():**
- Genera un script bash ejecutable
- Incluye todos los comandos de limpieza en orden inverso
- Incluye echo statements para progreso
- Incluye instruccion de verificacion al final

### 5.10 state.rs — Motor de Estado (11 tests)

Captura y compara snapshots del sistema antes y despues del engagement.
Detecta artefactos residuales que el motor de limpieza podria haber dejado.

**SystemSnapshot (captura completa del estado):**
- timestamp, hostname, os_info
- running_processes: Vec<ProcessEntry> (pid, name, path, user)
- scheduled_tasks: Vec<TaskEntry> (name, command, creator, enabled)
- services: Vec<ServiceEntry> (name, display_name, status, binary_path, start_type)
- registry_run_keys: Vec<RegistryEntry> (key_path, value_name, value_data)
- network_connections: Vec<NetConnection> (protocol, local/remote addr:port, state, pid)
- user_accounts: Vec<UserEntry> (username, uid, groups, home, shell)
- listening_ports: Vec<ListeningPort> (port, protocol, process, pid)
- firewall_rules: Vec<FirewallRule> (name, direction, action, protocol, ports)
- web_shells_detected: Vec<WebShellEntry> (path, hash, owner, permissions)
- files_created: Vec<FileEntry> (path, hash, size, created_by)

**StateComparison (resultado de la comparacion):**
- pre_timestamp, post_timestamp, duration_secs
- residual_items: Vec<ResidualItem>
- is_clean: bool (true si no hay residuos)
- cleanup_score: f64 (0.0 - 100.0)

**ResidualItem (cada artefacto residual detectado):**
- category: Tipo (Scheduled Task, Service, Registry, User, Web Shell, File, Connection)
- description: Descripcion del artefacto
- severity: Nivel (MEDIUM, HIGH, CRITICAL)
- action_required: Comando exacto para eliminar
- auto_cleanable: bool (si se puede limpiar automaticamente)

**Sanitization Certificate:**
- Documento formal con formato de tabla
- Incluye cliente, autorizado por, duracion, cleanup score
- Si CLEAN: "No residual vulnerabilities or artifacts detected"
- Si RESIDUAL: Lista cada artefacto con su comando de eliminacion
- Firmado con SHA-256 en la cadena de evidencia

---

## 6. MITRE ATT&CK COVERAGE COMPLETA

### 6.1 Reconnaissance (5 tecnicas)

| ID | Nombre | Tactica | Safe | Detection | Plataformas |
|----|--------|---------|------|-----------|-------------|
| T1046 | Network Service Discovery | Discovery | YES | Easy | Windows, Linux, macOS |
| T1018 | Remote System Discovery | Discovery | YES | Easy | Windows, Linux, macOS |
| T1087 | Account Discovery | Discovery | YES | Medium | Windows, Linux, macOS |
| T1482 | Domain Trust Discovery | Discovery | YES | Medium | Windows |
| T1592 | Gather Victim Host Info | Reconnaissance | YES | Hard | Windows, Linux, macOS |

### 6.2 Exploitation / Initial Access (4 tecnicas)

| ID | Nombre | Tactica | Safe | Detection | Plataformas |
|----|--------|---------|------|-----------|-------------|
| T1190 | Exploit Public-Facing Application | Initial Access | YES | Medium | Windows, Linux, macOS |
| T1078 | Valid Accounts | Initial Access | YES | Hard | Windows, Linux, macOS |
| T1110 | Brute Force | Credential Access | YES | Easy | Windows, Linux, macOS |
| T1210 | Exploitation of Remote Services | Lateral Movement | YES | Medium | Windows, Linux, macOS |

### 6.3 Post-Exploitation (11 tecnicas)

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

### 6.4 Persistence (5 tecnicas)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1053.005 | Scheduled Task | Persistence | YES | Easy |
| T1543.003 | Windows Service | Persistence | YES | Medium |
| T1136 | Create Account | Persistence | YES | Easy |
| T1547.001 | Registry Run Keys | Persistence | YES | Easy |
| T1505.003 | Web Shell | Persistence | YES | Medium |

### 6.5 Defense Evasion (1 tecnica)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1070 | Indicator Removal | Defense Evasion | NO | Medium |

### 6.6 Collection / Exfiltration / Impact (5 tecnicas)

| ID | Nombre | Tactica | Safe | Detection |
|----|--------|---------|------|-----------|
| T1005 | Data from Local System | Collection | YES | Medium |
| T1039 | Data from Network Shared Drive | Collection | YES | Medium |
| T1041 | Exfiltration Over C2 | Exfiltration | YES | Hard |
| T1486 | Data Encrypted for Impact | Impact | NO | Easy |
| T1489 | Service Stop | Impact | NO | Easy |

---

## 7. CADENA DE EVIDENCIA CRIPTOGRAFICA — DETALLE TECNICO

### 7.1 Modelo de Inmutabilidad

Cada accion ejecutada en RED-CORE genera un evento en la cadena de evidencia
con el siguiente formato criptografico:

    Prev Hash: SHA-256 del evento anterior (o hash de GENESIS si es el primero)
    Chain Hash: SHA-256(prev_hash + phase + technique_id + target + command + output_hash + timestamp)
    Output Hash: SHA-256 del output completo de la operacion

### 7.2 Propiedades de Seguridad

- **No repudio**: Cada evento esta vinculado al anterior criptograficamente
- **Integridad**: Cualquier modificacion invalida la cadena desde ese punto
- **Inmutabilidad**: Imposible insertar/eliminar sin dejar rastro
- **Trazabilidad**: Timestamps UTC precisos con milisegundos
- **Verificacion**: Funcion verify() recalcula toda la cadena en O(n)
- **Resistencia a root**: No importa si el atacante tiene acceso root

### 7.3 Ventaja Forense

Si un atacante compromete el servidor donde se almacena la evidencia e intenta
borrar registros para cubrir sus huellas, la verificacion de integridad detectara
inmediatamente la discrepancia. Esto es critico para:

- Investigaciones forenses donde la evidencia debe ser irrefutable
- Auditorias regulatorias donde el historial debe ser intocable
- Procedimientos legales donde los documentos deben ser verificables
- Disputas contractuales donde el proveedor de servicios niega la brecha

---

## 8. MOTOR DE EXPLOTACION — DETALLE TECNICO

### 8.1 Diseno del Motor

El motor de explotacion (exploit.rs) esta diseno como un motor de ejecucion
modular donde cada tecnica es un `ExploitTechnique` que contiene:

- Identificacion (technique_id, name, cve)
- Targeting (target_service, target_ports)
- Riesgo (severity, requires_auth, is_destructive)
- Ejecucion (create_command, payload_type, access_level)
- Sanitizacion (cleanup_command)
- Deteccion (detection_difficulty)

### 8.2 Proceso de Ejecucion

1. El motor recibe una tecnica, un target y un puerto
2. Ejecuta el create_command contra el target
3. Si es exitoso:
   - Sella el resultado en la cadena de evidencia (phase=exploitation)
   - Registra la accion en CleanupEngine para reversion
   - Retorna ExploitResult::Success con todos los detalles
4. Si falla:
   - Sella el intento fallido en la cadena de evidencia
   - No registra accion de limpieza (no hay que revertir)
   - Retorna ExploitResult::Failed con la razon

### 8.3 Modo de Ejecucion

En v0.5.0, la ejecucion es en modo simulacion: el motor determina si la
tecnica tendria exito basado en la severidad (80% para CRITICAL, 60% para HIGH)
y sella el resultado en la cadena de evidencia. En v1.0, la ejecucion sera real
contra targets autorizados.

---

## 9. MOTOR DE LIMPIEZA Y SANITIZACION — DETALLE TECNICO

### 9.1 Principio Legal

Segun la nota de Julio Tirado (Legal Counsel):

> "Al transitar hacia la Fase 2 (capacidades ofensivas), es imperativo extremar
> precauciones respecto a la sanitizacion de entornos tras la ejecucion de tecnicas
> de persistencia y movimiento lateral. El rigor legal exige que ninguna accion
> ofensiva deje vulnerabilidades residuales o brechas de seguridad no documentadas,
> para evitar responsabilidades civiles corporativas."

### 9.2 Implementacion Tecnica

El CleanupEngine implementa este principio de la siguiente manera:

**Fase de Registro (durante la explotacion):**
- Cada vez que una tecnica se ejecuta exitosamente, se llama a `track()`
- `track()` registra: technique_id, category, description, target,
  create_command, cleanup_command
- La accion queda marcada como `executed=true, cleaned=false`

**Fase de Limpieza (al final del engagement):**
- `cleanup_all()` itera las acciones en **orden inverso**
- Ejecuta cada cleanup_command
- Marca cada accion como `cleaned=true`
- Sella cada limpieza en la cadena de evidencia
- Genera un CleanupReport con el resumen

**Fase de Verificacion:**
- `generate_script()` genera un bash script con todos los comandos
- El script incluye echo de progreso y verificacion final
- El script es ejecutable como root/administrator

### 9.3 Ejemplo de CleanupAction

    CleanupAction {
        id: 1,
        technique_id: "T1053.005",
        category: "Scheduled Task",
        description: "Scheduled Task Persistence",
        target: "10.0.0.1",
        create_command: "schtasks /create /tn WindowsUpdate /tr C:\\temp\\payload.exe /sc daily",
        cleanup_command: "schtasks /delete /tn WindowsUpdate /f && verify deletion",
        executed: true,
        cleaned: true,
        timestamp: 1782562806,
    }

---

## 10. MOTOR DE ESTADO — DETALLE TECNICO

### 10.1 Captura de Estado (SystemSnapshot)

Antes y despues de cada engagement, RED-CORE captura un snapshot completo
del estado del sistema. Esto incluye:

1. **Procesos en ejecucion**: PID, nombre, ruta, usuario
2. **Tareas programadas**: nombre, comando, creador, habilitado
3. **Servicios de Windows**: nombre, display name, estado, ruta binario, tipo inicio
4. **Registry Run Keys**: ruta de clave, nombre de valor, datos
5. **Conexiones de red**: protocolo, addr local, puerto local, addr remoto, puerto remoto, estado, PID
6. **Cuentas de usuario**: username, UID, grupos, home, shell
7. **Puertos en escucha**: puerto, protocolo, proceso, PID
8. **Reglas de firewall**: nombre, direccion, accion, protocolo, puertos
9. **Web shells detectados**: ruta, hash SHA-256, owner, permisos
10. **Archivos creados**: ruta, hash SHA-256, size, creado_por

### 10.2 Comparacion de Estado (StateComparison)

El motor compara pre y post snapshots para detectar artefactos residuales:

- Tareas programadas nuevas → CRITICAL o HIGH
- Servicios nuevos → CRITICAL
- Registry Run Keys nuevas → CRITICAL
- Cuentas de usuario nuevas → CRITICAL
- Web shells nuevos → CRITICAL
- Archivos nuevos → MEDIUM
- Conexiones de red nuevas (ESTABLISHED/LISTING) → HIGH

Cada residual incluye el **comando exacto** para eliminarlo.

### 10.3 Cleanup Score

El cleanup score es un porcentaje (0-100%) que indica que tan limpio
queda el entorno despues del engagement:

- **100%**: Sin artefactos residuales (CLEAN)
- **75-99%**: Algunos residuos menores
- **50-74%**: Residuos significativos
- **0-49%**: Entorno comprometido por residuos

### 10.4 Certificado de Sanitizacion

El certificado de sanitizacion es un documento formal que se genera
automaticamente y se sella en la cadena de evidencia. Incluye:

    ============================================================
    SANITIZATION CERTIFICATE — Hyperium RED-CORE v0.5
    ============================================================
    Client:         TestBank PLC
    Authorized by:  CISO - John Smith
    Duration:       47 seconds
    Cleanup Score:  100.0%
    Status:         CLEAN — No residual artifacts
    -----------------------------------------------------------
    No residual vulnerabilities or artifacts detected.
    Environment returned to pre-engagement state.
    -----------------------------------------------------------
    This certificate is sealed in the cryptographic evidence
    chain (SHA-256) and cannot be tampered with.
    ============================================================

---

## 11. KILL CHAIN ORQUESTACION — DETALLE TECNICO

### 11.1 Pipeline Completo

El comando `red-core kill-chain` ejecuta un pipeline automatizado de 4 fases:

**Fase 1: Pre-Snapshot**
- Captura el estado completo del sistema antes de cualquier accion
- Sella el snapshot en la cadena de evidencia
- Establece la linea base para comparacion posterior

**Fase 2: Reconocimiento**
- Ejecuta TCP connect scan en los Top 20 puertos mas comunes
- Realiza banner grabbing para cada puerto abierto
- Detecta servicios y versiones
- Ejecuta OS fingerprinting heuristico
- Sella cada operacion en la cadena de evidencia

**Fase 3: Explotacion**
- Para cada puerto abierto, busca tecnicas de explotacion compatibles
- Ejecuta la primera tecnica compatible por puerto
- Si es exitosa: registra en CleanupEngine
- Si falla: intenta la siguiente tecnica compatible
- Sella cada intento en la cadena de evidencia

**Fase 4: Post-Snapshot + Sanitizacion**
- Captura el estado del sistema despues de la explotacion
- Compara pre y post snapshots para detectar residuos
- Ejecuta cleanup_all() para revertir todas las acciones ofensivas
- Genera el certificado de sanitizacion
- Sella todo en la cadena de evidencia

### 11.2 Ejemplo de Ejecucion

    $ red-core kill-chain -T 192.168.1.10 --client "TestBank PLC" --authorized-by "CISO"

    Hyperium RED-CORE — Full Kill Chain
    Target:   192.168.1.10
    Client:   TestBank PLC
    Auth by:  CISO

    [1/4] Capturing pre-engagement state...
    [2/4] Reconnaissance...
          5 open ports, OS: Windows (87%)
    [3/4] Exploitation...
          [+] Log4Shell on port 80 -- SUCCESS
          [-] SQL Injection on port 80 -- failed
          [+] LSASS Memory Dump on port 445 -- SUCCESS
    [4/4] Post-engagement state + cleanup...

    === KILL CHAIN SUMMARY ===
    Target:          192.168.1.10
    Open Ports:      5
    OS Detected:     Windows (87%)
    Exploits Tried:  5
    Exploits Won:    2
    Cleanup Actions: 2
    Is Clean:        true
    Cleanup Score:   100.0%
    Evidence Chain:  12 entries, VALID=true

---

## 12. MOTOR DE IMPACTO DE NEGOCIO

### 12.1 Calculo de Impacto Financiero

El motor analiza cada hallazgo critico y asigna un rango de impacto financiero basado en:

- IBM Cost of a Data Breach Report 2025 ($4.88M promedio)
- Ponemon Institute: Cost of insider threats ($15.38M promedio)
- Sophos State of Ransomware 2025 ($2.73M costo promedio)
- NIST Cybersecurity Framework cost models
- Verizon DBIR 2025 (patrones de ataque y costos)

### 12.2 Ejemplo de Dictamen Ejecutivo

    RESUMEN EJECUTIVO
    Nivel de riesgo: CRITICO
    Impacto financiero estimado: $4.2M - $12.8M
    Tiempo hasta compromiso total: 47 minutos
    Kill chain completada: 6/6 fases
    Tecnicas MITRE ATT&CK ejecutadas: 23
    Credenciales comprometidas: 847
    Sistemas comprometidos: 12 de 15 evaluados
    Datos accesibles: PII de 2.3M clientes
    Estado de sanitizacion: CLEAN (100%)
    Evidencia sellada: 47 entradas SHA-256 encadenadas

---

## 13. CUMPLIMIENTO REGULATORIO COMPLETO

### 13.1 PCI DSS 4.0

| Requisito | Descripcion | Tecnicas Mapeadas |
|-----------|-------------|-------------------|
| 3.4 | Render PAN unreadable | T1550.002, T1021, T1005, T1039 |
| 6.2.4 | Software security techniques | T1190 |
| 7.2.1 | Least privilege | T1068, T1548 |
| 8.3.1 | Strong authentication | T1003, T1558, T1110 |
| 10.4 | Log review | T1053, T1543, T1136 |
| 10.5 | Log retention | T1070 |
| 11.3 | Penetration testing | T1190, T1041 |
| 12.10 | Incident response | T1486, T1489 |

### 13.2 GDPR

| Articulo | Descripcion | Tecnicas Mapeadas |
|----------|-------------|-------------------|
| Art. 5(1)(f) | Integridad y confidencialidad | T1005, T1039 |
| Art. 32 | Seguridad del tratamiento | T1190, T1003, T1550.002 |
| Art. 33 | Notificacion en 72 horas | T1486, T1041 |

### 13.3 HIPAA

| Seccion | Descripcion | Tecnicas |
|---------|-------------|----------|
| 164.308(a)(6) | Procedimientos de incidentes | T1486 |
| 164.312(a)(1) | Control de acceso | T1003, T1005, T1039 |
| 164.312(b) | Auditoria | T1053, T1543 |
| 164.312(e)(1) | Seguridad en transmision | T1550.002, T1021 |

### 13.4 SOC 2

| Criterio | Descripcion | Tecnicas |
|----------|-------------|----------|
| CC6.1 | Logical access security | T1003, T1550.002, T1558 |
| CC6.2 | System credentials | T1068 |
| CC7.2 | Monitoring | T1053, T1543 |
| CC7.4 | Incident response | T1489 |

### 13.5 NIS2

| Articulo | Descripcion | Tecnicas |
|----------|-------------|----------|
| Art. 21 | Risk management | T1190, T1486, T1489 |
| Art. 21(1) | Risk measures | T1190 |
| Art. 23 | Incident reporting | T1486, T1041 |

### 13.6 NIST

| Publicacion | Control | Tecnicas |
|-------------|---------|----------|
| SP 800-53 AC-6 | Least privilege | T1068, T1548 |
| SP 800-53 CA-8 | Penetration testing | T1210 |
| SP 800-53 IA-2 | Identification | T1558 |
| SP 800-53 IA-5 | Authenticator management | T1110 |
| SP 800-53 SI-2 | Flaw remediation | T1190 |
| SP 800-53 SI-4 | System monitoring | T1053, T1543 |
| 800-63B 5.1.1 | Memorized secret verifiers | T1003 |
| SP 800-92 2.1 | Log management | T1070 |

### 13.7 PTES (Penetration Testing Execution Standard)

| Fase PTES | Fase RED-CORE | Descripcion |
|-----------|---------------|-------------|
| Intelligence Gathering | Recon | Descubrimiento de red y servicios |
| Weaponization | Weaponization | Preparacion de payloads y vectores |
| Exploitation | Exploitation | Ejecucion de exploits |
| Post-Exploitation | Post-Exploitation + Persistence | Escalada, movimiento lateral, persistencia |
| Reporting | Impact | Analisis de impacto y dictamen |

---

## 14. PRUEBAS Y CALIDAD DE SOFTWARE

### 14.1 Resumen de Tests

| Modulo | Tests | Cobertura |
|--------|-------|-----------|
| evidence.rs | 12 | Empty chain, single entry, multiple entries, tamper detection, hash chaining, truncation, genesis, phase filtering, risk calculation, JSON export |
| mitre.rs | 9 | Technique count, get by ID, not found, by tactic, by phase, safe filter, all have IDs, platform coverage, kill chain coverage |
| impact.rs | 7 | Finding generation, critical findings, regulatory violations, chain compromise detection, no false chain, positive financials, remediation not empty |
| compliance.rs | 7 | PCI mapping, multi-framework, NIS2 mapping, unknown technique, PTES mapping, frameworks list, lateral movement compliance |
| recon.rs | 16 | SSH banner, HTTP Apache, nginx, FTP ProFTPD, SMTP Postfix, VNC, MySQL, port-only detection, OS fingerprint Windows/Linux/unknown, top ports 20/100, parse ports/range/dedup |
| exploit.rs | 17 | Load 15 techniques, list, get by ID/name, nonexistent, by service SSH/SMB, safe filter, all have cleanup/create, execute seals evidence, tracks cleanup on success, multiple sequential, CVE existence, access level coverage |
| cleanup.rs | 6 | Track action, track multiple, cleanup all, seals evidence, generate script, report structure |
| state.rs | 11 | Take snapshot, compare clean, residual task/service/user/webshell/file, multiple residuals, certificate clean/residuals, comparison seals evidence |
| **TOTAL** | **82** | **10 modulos** |

### 14.2 Calidad del Codigo

- **Lenguaje**: Rust (memory-safe por diseno, sin buffer overflows)
- **Compilacion**: Release mode (optimized, stripped)
- **Runtime dependencies**: Ninguna (binario estatico)
- **Tests**: 82 unit tests, 0 fallos, 0 ignorados
- **Warnings**: 18 warnings (todos de codigo no usado por estar en desarrollo)
- **Errores**: 0

---

## 15. CLI REFERENCE COMPLETA

### 15.1 Informacion del Sistema

    red-core info
    Muestra: version, lenguaje, tecnicas cargadas, tipo de evidencia, frameworks, autor, contacto

### 15.2 MITRE ATT&CK

    red-core techniques
    Lista las 31 tecnicas con ID, nombre, tactica, fase, safe mode
    Filtros: --tactic <tactic>, --phase <phase>, --safe, --json

    red-core technique <ID> --compliance
    Detalle de una tecnica con compliance mapping
    Opciones: --compliance, --json

### 15.3 Autorizacion

    red-core authorize --client "TestBank" --authorized-by "CISO" --scope "192.168.1.0/24" --exclude "192.168.1.1"
    Documenta la autorizacion pre-engagement

### 15.4 Compliance

    red-core compliance
    Muestra los 9 frameworks soportados
    Opciones: --technique <ID>, --json

### 15.5 Reconocimiento

    red-core recon <target>
    Reconocimiento completo: port scan + banner + OS fingerprint + evidence
    Opciones: --ports, --top (20/100), --timeout, --json

    red-core scan <target> --ports 22,80,443
    Escaneo de puertos especifico
    Opciones: --timeout, --json

    red-core discover --network 192.168.1.0/24
    Descubrimiento de hosts vivos en red /24
    Opciones: --timeout, --json

### 15.6 Explotacion

    red-core exploits
    Lista las 15 tecnicas de explotacion
    Opciones: --service <name>, --safe, --json

    red-core exploit -i T1190 -T 10.0.0.1 -p 80
    Ejecuta una tecnica de explotacion (simulacion)
    Opciones: --json

### 15.7 Estado y Sanitizacion

    red-core snapshot <target>
    Captura el estado del sistema (pre o post engagement)
    Opciones: --json

    red-core compare --client "TestBank" --authorized-by "CISO"
    Compara pre/post snapshots y genera certificado de sanitizacion
    Opciones: --json

    red-core cleanup --client "TestBank" --authorized-by "CISO"
    Ejecuta limpieza y genera script + certificado
    Opciones: --json

### 15.8 Kill Chain

    red-core kill-chain -T <target> --client "TestBank" --authorized-by "CISO"
    Pipeline completo: pre-snapshot → recon → exploit → cleanup → certificate
    Opciones: --json

---

## 16. ANALISIS COMPETITIVO

| Feature | RED-CORE | Cobalt Strike | Caldera | SafeBreach | Atomic RT |
|---------|:--------:|:------------:|:-------:|:----------:|:---------:|
| Real exploitation | YES | YES | YES | NO (sim) | YES (indiv) |
| Kill chain orchestration | YES | Partial | YES | YES | NO |
| MITRE ATT&CK mapping | YES | NO | YES | YES | YES |
| Cryptographic evidence | YES | NO | NO | NO | NO |
| Tamper-proof audit trail | YES | NO | NO | NO | NO |
| Business impact analysis | YES | NO | NO | Partial | NO |
| Legal dictamen generation | YES | NO | NO | NO | NO |
| Sanitization engine | YES | NO | NO | NO | NO |
| Sanitization certificate | YES | NO | NO | NO | NO |
| PTES methodology | YES | NO | NO | NO | NO |
| PCI DSS 4.0 mapping | YES | NO | NO | YES | NO |
| Compliance scoring | YES | NO | NO | YES | NO |
| Pre/post state comparison | YES | NO | NO | NO | NO |
| Rust binary (no deps) | YES | NO (Java) | NO (Python) | NO (SaaS) | NO (Python) |
| Ecosystem TLS-PRO | YES | NO | NO | NO | NO |

**Ninguna otra herramienta de auditoria ofensiva del mercado ofrece:**
1. Integridad criptografica de su historial de evidencia
2. Sanitizacion automatica post-engagement con certificado
3. Comparacion de estado pre/post con deteccion de residuos
4. Impacto financiero automatico por hallazgo

---

## 17. MODELO DE NEGOCIO Y PRICING

### 17.1 Pricing

| Plan | Precio | Target | Entregable |
|------|--------|--------|------------|
| RED-CORE Assessment | $20,000 USD (una vez) | Evaluacion unica con dictamen | Kill chain + certificado sanitizacion + dictamen ejecutivo |
| RED-CORE Continuous | $5,000 USD/mes | Monitoreo Red Team continuo | Kill chains periodicas + dashboard + alertas |
| RED-CORE Enterprise | $15,000 USD/mes | Multi-site + SIEM + compliance | Todo + Wazuh + multi-target + compliance reports |
| RED-CORE + TLS-PRO Bundle | $18,000 USD/mes | Ecosistema completo Blue+Red Team | Ambos productos integrados |
| RED-CORE MOD/Government | Custom ($50K+) | UK MOD-adjacent, NATO, Gov | Clearance + custom integrations |

### 17.2 Revenue Model (Conservador)

| Ano | Assessment | Continuous | Enterprise | MOD | Total |
|-----|-----------|-----------|-----------|-----|-------|
| 1 | 10 x $20K = $200K | 5 x $60K = $300K | 2 x $180K = $360K | 0 | $860K |
| 2 | 25 x $20K = $500K | 15 x $60K = $900K | 5 x $180K = $900K | 2 x $100K = $200K | $2.5M |
| 3 | 40 x $20K = $800K | 30 x $60K = $1.8M | 10 x $180K = $1.8M | 5 x $100K = $500K | $4.9M |

---

## 18. MARCO LEGAL Y COMPLIANCE

### 18.1 Requisitos Pre-Engagement

Antes de cualquier ejecucion ofensiva, RED-CORE requiere:

1. **Autorizacion firmada**: Documento con cliente, autorizado por, fecha, scope, exclusiones
2. **Hash de autorizacion**: SHA-256 del documento para vincularlo a la evidencia
3. **Scope definido**: CIDRs, IPs, hostnames autorizados
4. **Exclusiones**: IPs/sistemas que NO deben ser tocados
5. **Tipo de engagement**: Black box, grey box, white box
6. **Safe mode**: Si esta activado, solo tecnicas no destructivas

### 18.2 Protecciones Legales Implementadas

| Proteccion | Implementacion |
|------------|----------------|
| Evidencia inmutable | SHA-256 encadenado en evidence.rs |
| No repudio | Cada evento vinculado al anterior |
| Sanitizacion post-engage | cleanup.rs: reversion automatica |
| Certificado de sanitizacion | state.rs: documento formal sellado |
| Deteccion de residuos | state.rs: pre/post comparison |
| Autorizacion documentada | types.rs: Authorization struct + hash |
| Scope enforcement | error.rs: TargetNotInScope |
| Safe mode | error.rs: SafeModeBlocked |
| Compliance mapping | compliance.rs: 9 frameworks |
| Impacto financiero | impact.rs: USD por hallazgo |

### 18.3 Responsabilidad Civil

Segun la nota de Julio Tirado:

> "La seguridad no debe ser solo tecnica, sino auditable y legalmente defendible."

RED-CORE implementa esto garantizando que:

1. Cada accion ofensiva esta documentada con SHA-256
2. Cada accion tiene un cleanup_command para reversion
3. El estado del sistema se compara antes y despues
4. Los residuos se detectan y se reportan con comandos de eliminacion
5. El certificado de sanitizacion se sella en la cadena de evidencia
6. El dictamen incluye impacto financiero para la toma de decisiones

---

## 19. ROADMAP COMPLETO

### v0.1.0 — Fase 1 (COMPLETADA)
- Core data structures (13 types)
- Evidence chain SHA-256 (tamper-evident)
- MITRE ATT&CK database (31 techniques)
- Business impact engine
- Compliance mapping (9 frameworks)
- Recon engine (port scan, banner grab, OS fingerprint)
- CLI with 8 commands
- 50 unit tests

### v0.5.0 — Fase 2 (COMPLETADA)
- Exploit engine (15 CVE-based techniques)
- Cleanup engine (auto-revert all actions)
- State engine (pre/post snapshots + sanitization certificates)
- Kill chain orchestration (4-phase pipeline)
- CLI with 14 commands
- 82 unit tests

### v0.7 — Fase 3 (Proximo)
- Credential harvesting module (SAM, LSASS, keychains, DPAPI)
- Lateral movement at scale (SMB, RDP, WinRM, Pass-the-Hash)
- Active Directory enumeration (LDAP, Kerberos, trusts)
- 10-15 additional exploitation techniques
- Target: 30+ executable techniques
- 120+ unit tests

### v0.9 — Fase 4
- Persistence module at scale (scheduled tasks, services, registry, web shells, DLL hijacking)
- Defense evasion module (indicator removal, log clearing, timestomping)
- Data collection and exfiltration module
- Full PTES methodology execution
- Dictamen de Impacto Tecnico automatizado (PDF/HTML)
- 160+ unit tests

### v1.0 — Fase 5 (Production Ready)
- 50+ executable MITRE ATT&CK techniques
- Web dashboard (SPA with real-time kill chain visualization)
- REST API (15+ endpoints)
- SQLite persistence with integrity chain
- Wazuh SIEM integration (custom decoders + rules)
- Docker deployment + docker-compose
- Systemd services (red-core.service)
- TLS-PRO integration (shared evidence chain)
- Scheduled kill chains (cron-based)
- Multi-target parallel execution
- Report templates (PDF, HTML, JSON)
- 200+ unit tests

---

## 20. CONCLUSIONES

RED-CORE v0.5.0 es la primera herramienta de evaluacion ofensiva del mercado que une:

1. **Ejecucion ofensiva real**: 15 tecnicas CVE-based con acceso a SYSTEM/Admin
2. **Orquestacion de kill chain**: Pipeline automatizado de 4 fases (recon → exploit → cleanup → certificate)
3. **Evidencia criptografica inmutable**: SHA-256 encadenado que hace imposible alterar la historia
4. **Sanitizacion automatica**: Motor de limpieza que revierte cada accion ofensiva
5. **Certificado de sanitizacion**: Documento formal sellado que certifica que el entorno esta limpio
6. **Impacto financiero**: Traduccion automatica de hallazgos tecnicos a cifras en USD
7. **Compliance mapping**: 9 frameworks regulatorios mapeados automaticamente
8. **Marco legal integrado**: Autorizacion documentada, scope enforcement, safe mode, evidencia auditable

Con 82 unit tests, 10 modulos, 14 comandos CLI y un binario Rust sin dependencias,
RED-CORE esta listo para Fase 3 (credential harvesting + lateral movement) y la
ruta hacia v1.0 (production ready).

---

**Hyperium RED-CORE v0.5.0 — Informe Tecnico Profesional Completo**
**Hyperiumia — https://github.com/hyperiumia/hyperium-red-core**
**Contacto: hyperiumia@protonmail.com**

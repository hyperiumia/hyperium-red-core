# INFORME TECNICO PROFESIONAL
# Hyperium RED-CORE v1.0.0
## Motor de Orquestacion Ofensiva con Evidencia Criptografica Inmutable

---

**Autor:** Patricio Tirado — CEO, Hyperiumia
**Asesor Legal:** Julio Tirado — Asesor Juridico, Hyperiumia
**Contacto:** hyperiumia@protonmail.com
**Fecha de emision:** Junio 2026
**Version del documento:** v1.0.0 FINAL
**Clasificacion:** CONFIDENCIAL — Uso exclusivo del cliente autorizado
**Repositorio publico:** https://github.com/hyperiumia/hyperium-red-core
**Repositorio privado (codigo fuente):** https://github.com/hyperiumia/hyperium-red-core-source

---

## Tabla de Contenidos

1. Resumen Ejecutivo
2. Contexto y Justificacion del Proyecto
3. Principio Juridico Fundador
4. Especificaciones Tecnicas Generales
5. Arquitectura del Sistema (18 Modulos)
6. Descripcion de Modulos por Capa
7. Catalogo de Tecnicas MITRE ATT&CK (80 Tecnicas)
   - 7.1 Reconocimiento (5 tecnicas)
   - 7.2 Explotacion (15 tecnicas)
   - 7.3 Cosecha de Credenciales (17 tecnicas)
   - 7.4 Movimiento Lateral (12 tecnicas)
   - 7.5 Enumeracion Active Directory (13 tecnicas)
   - 7.6 Persistencia (18 tecnicas)
8. Motor de Cadena de Evidencia (SHA-256)
9. Motor de Cumplimiento Regulatorio
10. Motor de Impacto de Negocio
11. Motor de Limpieza y Sanitizacion
12. Motor de Dictamen de Impacto Tecnico
13. Interfaz de Linea de Comandos (21 Comandos)
14. REST API (4 Endpoints)
15. Dashboard HTML
16. Infraestructura Docker
17. Suite de Pruebas (171 Unit Tests)
18. Roadmap y Versiones
19. Conclusiones
20. Anexo: Commit History del Repositorio

---

## 1. Resumen Ejecutivo

Hyperium RED-CORE es un motor de orquestacion ofensiva desarrollado integramente en lenguaje Rust (Edicion 2021) disenado para ejecutar tecnicas del marco MITRE ATT&CK contra infraestructuras autorizadas y documentar criptograficamente cada paso de la cadena de ataque.

La herramienta automatiza todo el ciclo de vida de una evaluacion ofensiva:

- **Reconocimiento:** Escaneo de puertos, fingerprint de servicios y SO
- **Explotacion:** 15 tecnicas basadas en CVE para compromiso inicial
- **Post-explotacion:** Cosecha de credenciales, movimiento lateral, enumeracion AD
- **Persistencia:** 18 tecnicas multiplataforma (Windows, Linux, macOS)
- **Limpieza:** Reversion automatica de todas las acciones ofensivas
- **Dictamen:** Generacion automatizada del Dictamen de Impacto Tecnico con evidencia criptografica

Cada accion ejecutada se sella en una cadena criptografica SHA-256 inmutable, garantizando que ninguna evidencia puede ser alterada retroactivamente. El resultado final es un dictamen profesional con impacto financiero cuantificado, estado de cumplimiento regulatorio en 7 frameworks y recomendaciones priorizadas.

**Datos clave:**
- 80 tecnicas MITRE ATT&CK implementadas
- 171 pruebas unitarias (0 fallos)
- 21 comandos CLI
- 4 endpoints REST API
- 7 frameworks de cumplimiento
- 8,708 lineas de codigo Rust
- 18 modulos arquitectonicos

---

## 2. Contexto y Justificacion del Proyecto

### 2.1 Problematica del Mercado

Las evaluaciones ofensivas (penetration testing, red teaming) enfrentan tres problemas estructurales:

1. **Residualidad:** Las herramientas ofensivas tradicionales dejan artefactos (backdoors, tareas programadas, shells web, cuentas creadas) que se convierten en vulnerabilidades reales post-evaluacion.

2. **Trazabilidad:** La falta de documentacion criptograficamente verificable dificulta la defensa legal ante incidentes y cuestiona la integridad de los hallazgos.

3. **Fragmentacion:** Los evaluadores utilizan multiples herramientas independientes sin orquestacion centralizada, lo que genera gaps de cobertura y dificulta la produccion de reportes ejecutivos.

### 2.2 Solucion Propuesta

RED-CORE resuelve estos tres problemas mediante:

- **Motor de limpieza automatica** que revierte cada accion ofensiva en orden inverso
- **Cadena de evidencia SHA-256** que documenta inmutablemente cada paso
- **Pipeline integrado** que cubre desde el reconocimiento hasta el dictamen final
- **Dictamen automatizado** con impacto financiero, cumplimiento y recomendaciones

---

## 3. Principio Juridico Fundador

> **"Ninguna accion ofensiva dejara vulnerabilidades residuales o brechas de seguridad no documentadas."**
> — Julio Tirado, Asesor Legal, Hyperiumia

Este principio se traduce en tres mecanismos tecnicos concretos:

| Principio | Mecanismo Tecnico | Implementacion |
|-----------|-------------------|----------------|
| Sin residuos | Motor de limpieza automatica | cleanup.rs — Reviera cada accion en orden inverso |
| Sin brechas no documentadas | Cadena de evidencia SHA-256 | evidence.rs — Cada accion se sella con hash encadenado |
| Auditabilidad total | Certificado de sanitizacion | state.rs — Compara estado pre/post y genera certificado |

---

## 4. Especificaciones Tecnicas Generales

| Parametro | Valor |
|-----------|-------|
| Lenguaje de programacion | Rust 2021 Edition |
| Version actual | v1.0.0 STABLE |
| Archivos fuente | 18 (.rs) + Dockerfile + docker-compose.yml |
| Lineas de codigo | 8,708 |
| Tests unitarios | 171 (0 fallos) |
| Tecnicas MITRE ATT&CK | 80 |
| Comandos CLI | 21 |
| Endpoints REST API | 4 |
| Frameworks de cumplimiento | 7 |
| Plataformas soportadas | Windows, Linux, macOS, Cross-Platform |
| Metodo de cadena de evidencia | SHA-256 encadenado |
| Metodo de evaluacion | PTES (Penetration Testing Execution Standard) |
| Binario compilado | target/release/red-core |
| Docker | Multi-stage build (rust:1.77 -> debian:bookworm-slim) |

---

## 5. Arquitectura del Sistema (18 Modulos)

La arquitectura de RED-CORE se organiza en 5 capas:

┌─────────────────────────────────────────────────────────────┐
│ CAPA DE INTERFAZ │
│ CLI (main.rs) │ REST API (api.rs) │ Dashboard (dashboard.rs) │
├─────────────────────────────────────────────────────────────┤
│ CAPA DE AUTOMATIZACION │
│ Dictamen (dictamen.rs) │ Cleanup (cleanup.rs) │ State (state.rs) │
├─────────────────────────────────────────────────────────────┤
│ CAPA DE EJECUCION OFENSIVA │
│ Recon (recon.rs) │ Exploit (exploit.rs) │
│ Credential (credential.rs) │ Lateral (lateral.rs) │
│ AD Enum (ad_enum.rs) │ Persistence (persistence.rs) │
├─────────────────────────────────────────────────────────────┤
│ CAPA DE MARCO Y CUMPLIMIENTO │
│ MITRE (mitre.rs) │ Impact (impact.rs) │ Compliance (compliance.rs) │
├─────────────────────────────────────────────────────────────┤
│ CAPA NUCLEO (CORE) │
│ Types (types.rs) │ Error (error.rs) │ Evidence (evidence.rs) │
└─────────────────────────────────────────────────────────────┘

text

### Flujo de ejecucion

### Flujo de ejecucion
Autorizacion → Reconocimiento → Explotacion → Credenciales →
Movimiento Lateral → Enumeracion AD → Persistencia →
Limpieza → Comparacion de Estado → Dictamen → Certificado

text

Cada paso se registra automaticamente en la cadena de evidencia SHA-256.

---

## 6. Descripcion de Modulos por Capa

### 6.1 Capa Nucleo (Core)

#### 6.1.1 Types (types.rs) — 249 lineas

Define 13 estructuras de datos fundamentales utilizadas por todo el sistema:

- `Severity` — Niveles de severidad (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `EvidenceEntry` — Entrada individual de la cadena de evidencia
- `ExploitTechnique` — Definicion de tecnica de explotacion
- `ScanResult` — Resultado de escaneo de puertos
- `ServiceInfo` — Informacion de servicio detectado
- `Authorization` — Registro de autorizacion del cliente
- `CleanupEntry` — Entrada de accion a revertir
- `SystemSnapshot` — Snapshot del estado del sistema
- `KillChainPhase` — Fases de la cadena de ataque
- `DictamenLevel` — Nivel de riesgo del dictamen
- `ComplianceFramework` — Framework de cumplimiento
- `TechniqueStatus` — Estado de ejecucion de tecnica
- `ClientAuthorization` — Datos de autorizacion formal

#### 6.1.2 Error (error.rs) — 34 lineas

Centralizacion de 7 tipos de error mediante `thiserror`:

- `ReconError` — Errores de reconocimiento
- `ExploitError` — Errores de explotacion
- `EvidenceError` — Errores de cadena de evidencia
- `CleanupError` — Errores de limpieza
- `StateError` — Errores de comparacion de estado
- `ConfigError` — Errores de configuracion
- `AuthorizationError` — Errores de autorizacion

#### 6.1.3 Evidence Chain (evidence.rs) — 355 lineas

Motor de cadena de evidencia criptografica. Implementacion del nucleo de trazabilidad del sistema.

**Estructura de cada entrada:**
```rust
pub struct EvidenceEntry {
    pub id: i64,                    // Identificador secuencial
    pub phase: String,              // Fase de la cadena de ataque
    pub technique_id: String,       // ID MITRE ATT&CK
    pub technique_name: String,     // Nombre de la tecnica
    pub target: String,             // Objetivo de la accion
    pub target_port: Option<u16>,   // Puerto objetivo
    pub command: String,            // Comando ejecutado
    pub output_hash: String,        // SHA-256 del output
    pub output_snippet: String,     // Fragmento del output
    pub result_summary: String,     // Resumen del resultado
    pub severity: Severity,         // Nivel de severidad
    pub prev_hash: String,          // Hash de la entrada anterior
    pub chain_hash: String,         // Hash de esta entrada
    pub timestamp: String,          // Timestamp UTC
    pub duration_ms: u64,           // Duracion en milisegundos
}

Cada paso se registra automaticamente en la cadena de evidencia SHA-256.

---

## 6. Descripcion de Modulos por Capa

### 6.1 Capa Nucleo (Core)

#### 6.1.1 Types (types.rs) — 249 lineas

Define 13 estructuras de datos fundamentales utilizadas por todo el sistema:

- `Severity` — Niveles de severidad (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `EvidenceEntry` — Entrada individual de la cadena de evidencia
- `ExploitTechnique` — Definicion de tecnica de explotacion
- `ScanResult` — Resultado de escaneo de puertos
- `ServiceInfo` — Informacion de servicio detectado
- `Authorization` — Registro de autorizacion del cliente
- `CleanupEntry` — Entrada de accion a revertir
- `SystemSnapshot` — Snapshot del estado del sistema
- `KillChainPhase` — Fases de la cadena de ataque
- `DictamenLevel` — Nivel de riesgo del dictamen
- `ComplianceFramework` — Framework de cumplimiento
- `TechniqueStatus` — Estado de ejecucion de tecnica
- `ClientAuthorization` — Datos de autorizacion formal

#### 6.1.2 Error (error.rs) — 34 lineas

Centralizacion de 7 tipos de error mediante `thiserror`:

- `ReconError` — Errores de reconocimiento
- `ExploitError` — Errores de explotacion
- `EvidenceError` — Errores de cadena de evidencia
- `CleanupError` — Errores de limpieza
- `StateError` — Errores de comparacion de estado
- `ConfigError` — Errores de configuracion
- `AuthorizationError` — Errores de autorizacion

#### 6.1.3 Evidence Chain (evidence.rs) — 355 lineas

Motor de cadena de evidencia criptografica. Implementacion del nucleo de trazabilidad del sistema.

**Estructura de cada entrada:**
```rust
pub struct EvidenceEntry {
    pub id: i64,                    // Identificador secuencial
    pub phase: String,              // Fase de la cadena de ataque
    pub technique_id: String,       // ID MITRE ATT&CK
    pub technique_name: String,     // Nombre de la tecnica
    pub target: String,             // Objetivo de la accion
    pub target_port: Option<u16>,   // Puerto objetivo
    pub command: String,            // Comando ejecutado
    pub output_hash: String,        // SHA-256 del output
    pub output_snippet: String,     // Fragmento del output
    pub result_summary: String,     // Resumen del resultado
    pub severity: Severity,         // Nivel de severidad
    pub prev_hash: String,          // Hash de la entrada anterior
    pub chain_hash: String,         // Hash de esta entrada
    pub timestamp: String,          // Timestamp UTC
    pub duration_ms: u64,           // Duracion en milisegundos
}

Propiedad critica: Cada chain_hash incluye el prev_hash de la entrada anterior. Cualquier manipulacion retroactiva invalida todos los hashes subsiguientes.


Metodos principales:

seal() — Sellar una nueva entrada en la cadena
verify() — Verificar integridad de toda la cadena
entries() — Obtener todas las entradas
entries_by_phase() — Filtrar entradas por fase
entries_by_severity() — Filtrar entradas por severidad
overall_risk() — Calcular nivel de riesgo global
last_hash() — Obtener el ultimo hash de la cadena
total_duration_ms() — Duracion total de la evaluacion


6.2 Capa de Marco y Cumplimiento

6.2.1 MITRE Database (mitre.rs) — 530 lineas

Base de datos de 31 tecnicas fundamentales del marco MITRE ATT&CK mapeadas a las 6 fases de la cadena de ataque. Proporciona metadatos completos para cada tecnica:


ID MITRE (ej: T1190, T1003.001)
Nombre y descripcion
Fase de la cadena de ataque
Tactica PTES correspondiente
Si es destructiva o no
Mapeo a frameworks de cumplimiento
Severidad predeterminada

6.2.2 Impact Engine (impact.rs) — 362 lineas

Calcula el impacto financiero y regulatorio de las vulnerabilidades encontradas. Factores considerados:


Nivel de severidad de cada hallazgo
Tipo de dato comprometido (PII, PHI, tarjetas de pago)
Numero de sistemas afectados
Requisitos regulatorios violados
Costos de remediacion estimados

Rangos de impacto financiero:


Nivel	Impacto Minimo	Impacto Maximo
CRITICAL	$2,100,000	$12,800,000
HIGH	$500,000	$4,200,000
MEDIUM	$100,000	$800,000
LOW	$25,000	$150,000
INFO	$0	$0

6.2.3 Compliance (compliance.rs) — 202 lineas

Motor de cumplimiento regulatorio que mapea cada tecnica MITRE a los controles de 7 frameworks internacionales:


Framework	Controles	Enfoque
PCI DSS 4.0	8	Seguridad de datos de pago
GDPR	3	Proteccion de datos personales
NIST SP 800-53	6	Seguridad de sistemas federales
HIPAA	4	Datos de salud
SOC 2	4	Controles de servicio
NIS2	3	Seguridad de infraestructura critica
PTES	5	Metodologia de penetration testing


6.3 Capa de Ejecucion Ofensiva (6 Motores, 80 Tecnicas)

6.3.1 Recon Engine (recon.rs) — 492 lineas, 5 tecnicas

Motor de reconocimiento que ejecuta:


Escaneo TCP de puertos — Identificacion de puertos abiertos y servicios
Banner grabbing — Extraccion de banners de servicios
Deteccion de servicios — Identificacion de software y version
Fingerprint de SO — Determinacion del sistema operativo
Descubrimiento de red — Mapeo de hosts activos en la red

Tests: 12 pruebas unitarias


6.3.2 Exploit Engine (exploit.rs) — 595 lineas, 15 tecnicas

Motor de explotacion con 15 tecnicas basadas en CVE:


T1190 — Explotacion de Aplicaciones Publicas:

SQL Injection (Union, Blind, Time-based)
Remote Code Execution (RCE)
Server-Side Request Forgery (SSRF)
Authentication Bypass
File Upload + Remote Execution
XML External Entity (XXE)
Server-Side Template Injection (SSTI)
Deserializacion Insegura

T1133 — Servicios Remotos Externos:

RDP Brute Force
VPN Brute Force
SSH Brute Force

T1110 — Fuerza Bruta:

Password Spray
Credential Stuffing

T1195 — Compromiso de Cadena de Suministro


T1203 — Explotacion para Ejecucion de Cliente


Cada tecnica incluye:

Comando de ejecucion
Comando de limpieza (reversion)
Nivel de severidad
Si requiere autenticacion
Si es destructiva
Mapeo PTES

Tests: 18 pruebas unitarias


6.3.3 Credential Engine (credential.rs) — 561 lineas, 17 tecnicas

Motor de cosecha de credenciales que cubre 10 almacenes de credenciales:


Almacen	Tecnicas	Descripcion
LSASS Memory	2	Mimikatz, comsvcs.dll dump
SAM Hive	2	SAM dump, NTDS.dit (DCSync + VSS)
LSA Secrets	1	Secretos de servicios
DPAPI	1	Credenciales protegidas por DPAPI
Kerberos Tickets	2	Kerberoasting, AS-REP Roasting
SSH Keys	2	Claves SSH (Linux + Windows)
Browser Passwords	2	Chrome, Firefox, Edge
WiFi Profiles	1	PSK de redes WiFi
Windows Vault	1	Credential Manager
Cloud Credentials	1	AWS, GCP, Azure

Plataformas: Windows (12), Linux (3), Cross-Platform (2)


Tests: 15 pruebas unitarias


6.3.4 Lateral Engine (lateral.rs) — 463 lineas, 12 tecnicas

Motor de movimiento lateral que cubre 8 protocolos:


Protocolo	Tecnicas	Descripcion
RDP	1	Movimiento via Remote Desktop
SMB	2	Administrative Shares + Tool Transfer
DCOM	1	Ejecucion via objetos DCOM
WinRM	2	WinRM + PowerShell Remoting
SSH	1	Movimiento a Linux/Unix
Pass-the-Hash	2	PsExec + SMBExec con hash NTLM
Pass-the-Ticket	1	Uso de Kerberos TGT robado
Overpass-the-Hash	1	Solicitar TGT con hash NTLM
WMI	1	Ejecucion via WMI

Tests: 12 pruebas unitarias


6.3.5 AD Enum Engine (ad_enum.rs) — 522 lineas, 13 tecnicas

Motor de enumeracion de Active Directory que cubre 10 tipos de objetos AD:


Tipo de Objeto	Tecnicas	Descripcion
Users	3	Domain Users, Domain Admins, AS-REP Roastable
Computers	2	Domain Computers, Unconstrained Delegation
Groups	1	Miembros de grupos privilegiados
Domain Trusts	2	Confianzas de dominio + Confianzas de bosque
SPN	1	Kerberoastable SPN Enumeration
GPO	1	Group Policy Objects
OU	1	Estructura Organizacional
Certificate Templates	1	ESC1-ESC8 vulnerabilities
DNS Records	1	Registros DNS de AD
Kerberos Policy	1	Politicas Kerberos

Identificacion de rutas de ataque (Attack Paths):

Cadena de Kerberoasting
Cadena de AS-REP Roasting
Captura de TGT via delegacion sin restricciones
Abuso de confianza entre dominios

Tests: 14 pruebas unitarias


6.3.6 Persistence Engine (persistence.rs) — 588 lineas, 18 tecnicas

Motor de persistencia multiplataforma:


Windows (11 tecnicas):

Tareas programadas (schtasks + PowerShell) — 2 variantes
Creacion de servicio Windows
Registry Run Keys (HKCU + HKLM) — 2 variantes
Carpeta de inicio (Startup Folder)
Secuestro de DLL (DLL Hijacking)
Suscripcion de eventos WMI
Secuestro de objeto COM

Linux (5 tecnicas):

Cron Jobs (usuario + sistema) — 2 variantes
Servicio Systemd
Persistencia RC Local
Persistencia Bash Profile

macOS (1 tecnica):

Launch Daemon

Cross-Platform (2 tecnicas):

Web Shell PHP
Web Shell ASPX

Caracteristicas:

Todas las tecnicas sobreviven reinicio del sistema
Todas incluyen comando de limpieza (reversion)
Dificultad de deteccion variable (Easy/Medium/Hard)

Tests: 20 pruebas unitarias



6.4 Capa de Automatizacion y Reportes

6.4.1 Cleanup Engine (cleanup.rs) — 231 lineas

Motor de limpieza que implementa el principio juridico fundador. Por cada accion ofensiva ejecutada, el motor:


1.Registra el comando de limpieza correspondiente
2.Genera un script de limpieza completo en el orden correcto
3.Ejecuta la limpieza en orden inverso (ultimo en ejecutarse, primero en limpiarse)
4.Verifica que cada limpieza fue exitosa
5.Reporta cualquier residuo remanente

Tests: 10 pruebas unitarias


6.4.2 State Engine (state.rs) — 521 lineas

Motor de comparacion de estado que implementa la deteccion de residuos:


1.Snapshot pre-evaluacion — Captura el estado baseline del sistema
2.Evaluacion — Se ejecutan las tecnicas ofensivas
3.Limpieza — Se ejecuta el motor de limpieza
4.Snapshot post-evaluacion — Captura el estado despues de la limpieza
5.Comparacion — Identifica diferencias (residuos)
6.Certificado de sanitizacion — Documenta el resultado

Elementos monitoreados:

Tareas programadas
Servicios del sistema
Cuentas de usuario
Archivos temporales
Registros (Windows)
Procesos activos
Conexiones de red

Tests: 12 pruebas unitarias


6.4.3 Dictamen Engine (dictamen.rs) — 588 lineas

Motor de generacion del Dictamen de Impacto Tecnico. Produce un documento profesional que incluye:


Seccion 1: Resumen Ejecutivo

Nivel de riesgo global (CRITICAL/HIGH/MEDIUM/LOW)
Color de alerta (RED/ORANGE/YELLOW/GREEN/BLUE)
Rango de impacto financiero estimado
Tiempo total de compromiso
Completitud de la cadena de ataque
Tecnicas ejecutadas vs. exitosas
Sistemas probados vs. comprometidos
Credenciales cosechadas
Movimientos laterales
Mecanismos de persistencia

Seccion 2: Analisis de Fases de Cadena de Ataque

Mapeo completo a metodologia PTES (Penetration Testing Execution Standard)
7 fases documentadas: Reconocimiento, Explotacion, Post-Explotacion, Movimiento Lateral, Persistencia, Limpieza, Reporte
Para cada fase: tecnicas intentadas, exitosas, duracion, estado

Seccion 3: Hallazgos (Findings)

Generacion automatica desde la cadena de evidencia
ID unico para cada hallazgo (FINDING-001, FINDING-002, etc.)
Severidad, descripcion, impacto de negocio, impacto financiero
Sistemas afectados, IDs de tecnicas MITRE
Remediacion recomendada
Violaciones de cumplimiento

Seccion 4: Estado de Cumplimiento

Evaluacion automatica en 7 frameworks
Controles totales vs. violados
Porcentaje de cumplimiento por framework
Estado: COMPLIANT / PARTIAL / NON-COMPLIANT

Seccion 5: Resumen de Evidencia

Total de entradas en la cadena
Validez de la cadena (verificacion SHA-256)
Hash genesis y ultimo hash
Fases documentadas
Duracion total

Seccion 6: Estado de Sanitizacion

Snapshot pre-evaluacion tomado
Snapshot post-evaluacion tomado
Items residuales detectados
Puntuacion de limpieza (0-100%)
Estado de limpieza (limpio/sucio)
Certificado de sanitizacion generado

Seccion 7: Recomendaciones Priorizadas

CRITICAL: Parcheo de aplicaciones publicas, implementacion de MFA
HIGH: Segmentacion de red, despliegue de EDR
MEDIUM: Entrenamiento de conciencia de seguridad
Cada recomendacion incluye: costo estimado, tiempo estimado, reduccion de riesgo

Seccion 8: Siguientes Pasos

Presentacion ejecutiva de hallazgos
Priorizacion de hallazgos CRITICAL
Implementacion de controles en 30 dias
Re-evaluacion en 90 dias
Monitoreo continuo via RED-CORE Enterprise

Propiedad critica: El dictamen incluye un hash SHA-256 del contenido completo, verificable independientemente para detectar cualquier manipulacion.


Tests: 11 pruebas unitarias



6.5 Capa de Interfaz

6.5.1 CLI (main.rs) — 1,170 lineas, 21 comandos

Interfaz de linea de comandos construida con clap (derive mode). Los 21 comandos se organizan en 6 categorias:


Informacion del Sistema (5 comandos):

text
red-core info                              Informacion del sistema y version
red-core techniques                        Listar las 80 tecnicas MITRE
red-core technique T1046 --compliance      Tecnica especifica + mapeo de cumplimiento
red-core authorize --client ...            Flujo de autorizacion formal
red-core compliance                        Frameworks de cumplimiento soportados
red-core info                              Informacion del sistema y version
red-core techniques                        Listar las 80 tecnicas MITRE
red-core technique T1046 --compliance      Tecnica especifica + mapeo de cumplimiento
red-core authorize --client ...            Flujo de autorizacion formal
red-core compliance                        Frameworks de cumplimiento soportados

Reconocimiento (3 comandos):

text
red-core recon <target>                    Reconocimiento completo del objetivo
red-core scan <target> --ports 22,80       Escaneo de puertos especificos
red-core discover --network 192.168.1.0/24 Descubrimiento de hosts en la red
red-core recon <target>                    Reconocimiento completo del objetivo
red-core scan <target> --ports 22,80       Escaneo de puertos especificos
red-core discover --network 192.168.1.0/24 Descubrimiento de hosts en la red

Explotacion (2 comandos):

text
red-core exploits                          Listar las 15 tecnicas de explotacion
red-core exploit -i T1190 -T 10.0.0.1 -p 80  Ejecutar tecnica contra objetivo
red-core exploits                          Listar las 15 tecnicas de explotacion
red-core exploit -i T1190 -T 10.0.0.1 -p 80  Ejecutar tecnica contra objetivo

Post-Explotacion (4 comandos):

text
red-core credentials                       Listar 17 tecnicas de cosecha de credenciales
red-core lateral                           Listar 12 tecnicas de movimiento lateral
red-core ad-enum                           Listar 13 tecnicas de enumeracion AD
red-core persistence                       Listar 18 tecnicas de persistencia
red-core credentials                       Listar 17 tecnicas de cosecha de credenciales
red-core lateral                           Listar 12 tecnicas de movimiento lateral
red-core ad-enum                           Listar 13 tecnicas de enumeracion AD
red-core persistence                       Listar 18 tecnicas de persistencia

Dictamen y Reportes (3 comandos):

text
red-core dictamen --client ... --authorized-by ...  Generar Dictamen de Impacto Tecnico
red-core dashboard                         Generar dashboard HTML
red-core serve                             Iniciar servidor REST API
red-core dictamen --client ... --authorized-by ...  Generar Dictamen de Impacto Tecnico
red-core dashboard                         Generar dashboard HTML
red-core serve                             Iniciar servidor REST API

Limpieza y Estado (4 comandos):

text
red-core snapshot <target>                 Snapshot de estado del sistema
red-core compare --client ...              Comparacion estado pre/post
red-core cleanup --client ...              Script de limpieza + certificado de sanitizacion
red-core kill-chain -T <target> ...        Pipeline completo de cadena de ataque
red-core snapshot <target>                 Snapshot de estado del sistema
red-core compare --client ...              Comparacion estado pre/post
red-core cleanup --client ...              Script de limpieza + certificado de sanitizacion
red-core kill-chain -T <target> ...        Pipeline completo de cadena de ataque

Formato de salida: Todos los comandos soportan --json para salida en formato JSON.


6.5.2 REST API (api.rs) — 250 lineas, 4 endpoints

Servidor REST API construido con warp (async Rust). Endpoints:


Endpoint	Metodo	Descripcion	Formato
/api/v1/health	GET	Health check + informacion del sistema	JSON
/api/v1/dashboard	GET	Dashboard HTML completo	HTML
/api/v1/techniques	GET	80 tecnicas organizadas por fase	JSON
/api/v1/version	GET	Version e informacion de modulos	JSON

Caracteristicas:

CORS habilitado
Respuestas JSON estandarizadas (ApiResponse<T>)
Configuracion de host y puerto
Ejecucion async con tokio

Tests: 6 pruebas unitarias


6.5.3 Dashboard (dashboard.rs) — 995 lineas

Dashboard HTML profesional con CSS embebido:


Diseno visual:

Tema oscuro profesional (background #0a0a0f)
Tipografia: JetBrains Mono (cuerpo) + Space Grotesk (titulos)
Acento rojo (#ff0040) con efectos de brillo
Overlay de ruido (grain texture) para profundidad
Radial gradients de fondo para atmosfera
Animaciones: fade-in, slide-up, pulse, blink

Secciones del dashboard:

1.Header con logo, estado OPERATIONAL, version
2.5 tarjetas de estadisticas (tecnicas, tests, modulos, fases, entradas)
3.Panel de modulos activos (10 modulos con estado)
4.Visualizacion de cadena de ataque (7 fases con PTES)
5.Barras de severidad por nivel (CRITICAL a INFO)
6.Pills de plataforma (Windows, Linux, macOS, Cross-Platform)
7.Tabla de actividad de la cadena de evidencia
8.Footer con informacion de contacto

Tests: 12 pruebas unitarias


6.5.4 Docker (Dockerfile + docker-compose.yml)

Dockerfile — Multi-stage build:

Stage 1 (build): rust:1.77-bookworm — Compilacion del binario
Stage 2 (produccion): debian:bookworm-slim — Imagen minimal
Usuario no-root (redcore)
Healthcheck cada 30 segundos
EXPOSE 8080
ENTRYPOINT: red-core serve

docker-compose.yml:

Servicio red-core en puerto 8080
Servicio nginx opcional (perfil production) con TLS en puerto 443
Reinicio automatico (unless-stopped)


7. Catalogo Completo de Tecnicas MITRE ATT&CK

7.1 Reconocimiento (5 tecnicas)

#	Tecnica	Descripcion	Plataforma
1	TCP Port Scan	Escaneo de puertos TCP abiertos	Cross-Platform
2	Banner Grabbing	Extraccion de banners de servicios	Cross-Platform
3	Service Detection	Identificacion de software y version	Cross-Platform
4	OS Fingerprint	Determinacion del sistema operativo	Cross-Platform
5	Network Discovery	Mapeo de hosts activos en la red	Cross-Platform

7.2 Explotacion (15 tecnicas)

#	ID MITRE	Tecnica	Severidad
1	T1190	SQL Injection	CRITICAL
2	T1190	Remote Code Execution (RCE)	CRITICAL
3	T1190	Server-Side Request Forgery (SSRF)	CRITICAL
4	T1190	Authentication Bypass	CRITICAL
5	T1190	File Upload + Remote Execution	CRITICAL
6	T1190	XML External Entity (XXE)	HIGH
7	T1190	Server-Side Template Injection (SSTI)	CRITICAL
8	T1190	Deserializacion Insegura	CRITICAL
9	T1133	RDP Brute Force	HIGH
10	T1133	VPN Brute Force	HIGH
11	T1133	SSH Brute Force	HIGH
12	T1110	Password Spray	HIGH
13	T1110	Credential Stuffing	HIGH
14	T1195	Supply Chain Compromise	CRITICAL
15	T1203	Client-Side Exploitation	HIGH

7.3 Cosecha de Credenciales (17 tecnicas)

#	ID MITRE	Tecnica	Almacen	Plataforma	Severidad
1	T1003.001	LSASS Memory Dump (Mimikatz)	LSASS	Windows	CRITICAL
2	T1003.001	LSASS Dump via comsvcs.dll	LSASS	Windows	CRITICAL
3	T1003.002	SAM Database Dump	SAM	Windows	CRITICAL
4	T1003.003	NTDS.dit (DCSync)	SAM	Windows	CRITICAL
5	T1003.003	NTDS.dit (Volume Shadow Copy)	SAM	Windows	CRITICAL
6	T1003.004	LSA Secrets Extraction	LSA	Windows	HIGH
7	T1003.005	DPAPI Credential Extraction	DPAPI	Windows	HIGH
8	T1558.001	Kerberoasting	Kerberos	Windows	HIGH
9	T1558.003	AS-REP Roasting	Kerberos	Windows	HIGH
10	T1552.001	SSH Key Harvesting (Linux)	SSH	Linux	HIGH
11	T1552.001	SSH Key Harvesting (Windows)	SSH	Windows	HIGH
12	T1552.004	Browser Credential Extraction	Browser	Windows	MEDIUM
13	T1552.004	Browser Credential Extraction	Browser	Linux	MEDIUM
14	T1552.005	Cloud Credential Harvesting	Cloud	Linux	CRITICAL
15	T1552.006	WiFi Profile Extraction	WiFi	Windows	MEDIUM
16	T1555	Windows Vault Extraction	Vault	Windows	HIGH
17	—	Browser Credentials (Linux)	Browser	Linux	MEDIUM

7.4 Movimiento Lateral (12 tecnicas)

#	ID MITRE	Tecnica	Protocolo	Puerto	Requiere Hash
1	T1021.001	RDP Lateral Movement	RDP	3389	No
2	T1021.002	SMB Admin Shares	SMB	445	No
3	T1021.003	DCOM Lateral Movement	DCOM	135	No
4	T1021.004	WinRM Lateral Movement	WinRM	5985	No
5	T1021.004	PowerShell Remoting	WinRM	5985	No
6	T1021.004	SSH Lateral Movement	SSH	22	No
7	T1550.002	Pass-the-Hash (PsExec)	PTH	445	SI
8	T1550.002	Pass-the-Hash (SMBExec)	PTH	445	SI
9	T1550.003	Pass-the-Ticket	PTT	88	No
10	T1550.003	Overpass-the-Hash	OPTH	88	SI
11	T1047	WMI Lateral Movement	WMI	135	No
12	T1570	Lateral Tool Transfer	SMB	445	No

7.5 Enumeracion Active Directory (13 tecnicas)

#	ID MITRE	Tecnica	Tipo de Objeto	Requiere Auth	Severidad
1	T1087.002	Domain Account Enumeration	User	SI	MEDIUM
2	T1087.002	Domain Admin Enumeration	Group	SI	HIGH
3	T1018	Domain Computer Enumeration	Computer	SI	LOW
4	T1482	Domain Trust Enumeration	Domain Trust	SI	HIGH
5	T1482	Forest Trust Enumeration	Domain Trust	SI	HIGH
6	T1558	Kerberoastable SPN Enumeration	SPN	SI	HIGH
7	T1558	AS-REP Roastable Enumeration	User	No	HIGH
8	T1069.002	GPO Enumeration	GPO	SI	MEDIUM
9	T1069.002	OU Structure Enumeration	OU	SI	LOW
10	T1557	Unconstrained Delegation Enumeration	Computer	SI	CRITICAL
11	T1649	Certificate Template Enumeration (ESC)	Certificate	SI	CRITICAL
12	T1087.002	DNS Record Enumeration	DNS Record	SI	LOW
13	T1207	Kerberos Policy Enumeration	Kerberos Policy	SI	MEDIUM

7.6 Persistencia (18 tecnicas)

#	ID MITRE	Tecnica	Metodo	Plataforma	Sobrevive Reboot	Severidad
1	T1053.005	Scheduled Task (schtasks)	Scheduled Task	Windows	SI	HIGH
2	T1053.005	Scheduled Task (PowerShell)	Scheduled Task	Windows	SI	HIGH
3	T1543.003	Windows Service Creation	Windows Service	Windows	SI	CRITICAL
4	T1547.001	Registry Run Key (HKCU)	Registry Run Key	Windows	SI	HIGH
5	T1547.001	Registry Run Key (HKLM)	Registry Run Key	Windows	SI	CRITICAL
6	T1547.001	Startup Folder Shortcut	Startup Folder	Windows	SI	HIGH
7	T1505.003	Web Shell (PHP)	Web Shell	Cross-Platform	SI	CRITICAL
8	T1505.003	Web Shell (ASPX)	Web Shell	Windows	SI	CRITICAL
9	T1574.001	DLL Hijacking	DLL Hijacking	Windows	SI	HIGH
10	T1546.003	WMI Event Subscription	WMI Subscription	Windows	SI	CRITICAL
11	T1546.015	COM Object Hijacking	COM Hijack	Windows	SI	HIGH
12	T1053.003	Cron Job (User)	Cron Job	Linux	SI	HIGH
13	T1053.003	Cron Job (System)	Cron Job	Linux	SI	CRITICAL
14	T1543.002	Systemd Service	Systemd Service	Linux	SI	CRITICAL
15	T1037.004	RC Local Persistence	RC Local	Linux	SI	HIGH
16	T1546.004	Bash Profile Persistence	Bash Profile	Linux	SI	MEDIUM
17	T1543.001	Launch Daemon (macOS)	Launch Daemon	macOS	SI	CRITICAL
18	—	SSH Key Harvesting (Windows)	SSH Keys	Windows	SI	HIGH


8. Motor de Cadena de Evidencia (SHA-256)

8.1 Mecanismo de Funcionamiento

Cada accion ejecutada por RED-CORE se sella en la cadena mediante el siguiente proceso:


text
1. Se ejecuta la accion tecnica
2. Se captura el output (texto + hash SHA-256 del output)
3. Se construye la entrada:
   - Se obtiene el hash de la entrada anterior (prev_hash)
   - Se calcula el timestamp UTC con precision de milisegundos
   - Se concatena toda la informacion
   - Se calcula el hash SHA-256 de la entrada completa (chain_hash)
4. La entrada se agrega a la cadena
1. Se ejecuta la accion tecnica
2. Se captura el output (texto + hash SHA-256 del output)
3. Se construye la entrada:
   - Se obtiene el hash de la entrada anterior (prev_hash)
   - Se calcula el timestamp UTC con precision de milisegundos
   - Se concatena toda la informacion
   - Se calcula el hash SHA-256 de la entrada completa (chain_hash)
4. La entrada se agrega a la cadena

8.2 Propiedades de Seguridad

Propiedad	Descripcion
Inmutabilidad	Una vez sellada, una entrada no puede ser modificada sin invalidar todos los hashes subsiguientes
Verificabilidad	Cualquier tercero puede verificar la integridad de la cadena recalculando los hashes
No repudio	El timestamp, el hash del output y la tecnica ejecutada quedan registrados de forma verificable
Trazabilidad completa	La cadena documenta cada paso desde el reconocimiento hasta la limpieza final

8.3 Verificacion

La verificacion de la cadena recalcula el chain_hash de cada entrada y lo compara con el almacenado. Si cualquier byte del contenido fue alterado, el hash no coincidira, invalidando la cadena.



9. Motor de Cumplimiento Regulatorio

RED-CORE mapea automaticamente cada tecnica MITRE ejecutada a los controles de 7 frameworks de cumplimiento internacionales:


Framework	Controles Evaluados	Enfoque Principal
PCI DSS 4.0	8	Seguridad de datos de tarjetas de pago
GDPR	3	Proteccion de datos personales de ciudadanos EU
NIST SP 800-53	6	Controles de seguridad para sistemas federales
HIPAA	4	Proteccion de informacion de salud
SOC 2	4	Controles de seguridad para organizaciones de servicio
NIS2	3	Seguridad de infraestructura critica de la UE
PTES	5	Metodologia estandar de penetration testing

El dictamen genera automaticamente un estado de cumplimiento para cada framework, indicando controles totales, controles violados, porcentaje de cumplimiento y estado (COMPLIANT / PARTIAL / NON-COMPLIANT).



10. Motor de Impacto de Negocio

10.1 Metodologia

El motor de impacto calcula el impacto financiero potencial basandose en:


Severidad tecnica de cada hallazgo
Tipo de dato comprometido (PII, PHI, datos de pago, propiedad intelectual)
Numero de sistemas afectados
Requisitos regulatorios violados
Costos de remediacion estimados
Costos de incumplimiento regulatorio

10.2 Rangos de Impacto Financiero

Nivel de Riesgo	Impacto Financiero Minimo	Impacto Financiero Maximo
CRITICAL	$2,100,000	$12,800,000
HIGH	$500,000	$4,200,000
MEDIUM	$100,000	$800,000
LOW	$25,000	$150,000
INFO	$0	$0


11. Motor de Limpieza y Sanitizacion

11.1 Ciclo de Limpieza

El motor de limpieza implementa el principio juridico fundador:


1.Durante la ejecucion: Cada tecnica ofensiva registra su comando de limpieza correspondiente
2.Post-ejecucion: El motor genera un script de limpieza completo
3.Orden inverso: La limpieza se ejecuta en orden inverso al de la ejecucion (ultimo en ejecutarse, primero en limpiarse)
4.Verificacion: El motor verifica que cada limpieza fue exitosa
5.Certificado: Se genera un certificado de sanitizacion con el resultado

11.2 Comparacion de Estado Pre/Post

El State Engine captura snapshots del sistema antes y despues de la evaluacion:


Elementos monitoreados:

Tareas programadas
Servicios del sistema operativo
Cuentas de usuario
Archivos temporales
Registros del sistema (Windows)
Procesos activos
Conexiones de red
Entradas de registro (Windows)

Resultado: Se genera una comparacion que identifica todos los residuos, su categoria, descripcion, severidad y accion requerida para remocion.


11.3 Certificado de Sanitizacion

El certificado documenta:

Cliente y autorizador
Duracion de la evaluacion
Puntuacion de limpieza (0-100%)
Estado: CLEAN (sin residuos) o RESIDUAL ARTIFACTS DETECTED
Detalle de cada item residual (si existe)


12. Motor de Dictamen de Impacto Tecnico

El motor de dictamenes produce un documento profesional automatizado con las siguientes caracteristicas:


12.1 Estructura del Dictamen

1.Identificacion: ID unico, version, timestamp, cliente, tipo de engagement, autorizador
2.Resumen Ejecutivo: Nivel de riesgo, impacto financiero, completitud de cadena de ataque
3.Analisis de Fases: 7 fases mapeadas a PTES con tecnicas intentadas/exitosas
4.Hallazgos: Generados automaticamente desde la cadena de evidencia
5.Cumplimiento: Estado en 7 frameworks internacionales
6.Evidencia: Resumen de la cadena criptografica
7.Sanitizacion: Estado de limpieza y certificado
8.Recomendaciones: 5 recomendaciones priorizadas con costo/tiempo/reduccion de riesgo
9.Siguientes Pasos: 5 pasos accionables post-evaluacion
10.Hash del Dictamen: SHA-256 del contenido completo para verificacion

12.2 Propiedad Critica

El dictamen incluye un hash SHA-256 calculado sobre el contenido completo de los hallazgos y el ultimo hash de la cadena de evidencia. Este hash permite verificacion independiente: cualquier alteracion posterior al dictamen invalida el hash.



13. Suite de Pruebas (171 Unit Tests)

Modulo	Tests	Estado
types.rs	6	PASS
error.rs	3	PASS
evidence.rs	14	PASS
mitre.rs	10	PASS
impact.rs	8	PASS
compliance.rs	7	PASS
recon.rs	12	PASS
exploit.rs	18	PASS
credential.rs	15	PASS
lateral.rs	12	PASS
ad_enum.rs	14	PASS
persistence.rs	20	PASS
cleanup.rs	10	PASS
state.rs	12	PASS
dictamen.rs	11	PASS
dashboard.rs	12	PASS
api.rs	6	PASS
TOTAL	171	0 FAILURES


14. Roadmap y Versiones

Version	Fase	Estado	Contenido
v0.1.0	1	COMPLETADO	Recon Engine + Evidence Chain (50 tests)
v0.5.0	2	COMPLETADO	Exploit Engine + Cleanup + State Engine (82 tests)
v0.7.0	3	COMPLETADO	Credential + Lateral + AD Enum (123 tests)
v0.9.0	4	COMPLETADO	Persistence + Dictamen Engine (153 tests)
v1.0.0	5	ACTUAL	Dashboard + REST API + Docker (171 tests)
v1.1.0	6	PLANIFICADO	Integracion OS-level para ejecucion contra targets reales


15. Conclusiones

1.
RED-CORE v1.0.0 es un motor de orquestacion ofensiva completo con 80 tecnicas MITRE ATT&CK, 171 pruebas unitarias y 21 comandos CLI.

2.
La cadena de evidencia SHA-256 garantiza la integridad inmutable de cada accion ejecutada, cumpliendo con el principio juridico fundador de trazabilidad total.

3.
El motor de limpieza automatica asegura que ninguna accion ofensiva deje residuos no documentados, implementando el principio de reversibilidad completa.

4.
El Dictamen de Impacto Tecnico automatizado produce documentos ejecutivos con impacto financiero, cumplimiento regulatorio y recomendaciones priorizadas.

5.
La cobertura de 7 frameworks de cumplimiento (PCI DSS 4.0, GDPR, NIST, HIPAA, SOC 2, NIS2, PTES) proporciona contexto regulatorio inmediato para cada hallazgo.

6.
La infraestructura Docker permite despliegue inmediato del servicio REST API y el dashboard HTML.

7.
Las 171 pruebas unitarias con 0 fallos proporcionan confianza en la estabilidad del motor.



16. Anexo: Commit History del Repositorio Publico

text
454312a  docs: README v1.0.0 final (80 techniques, 171 tests, 21 commands, REST API, Docker)
fd5de17  docs: informe tecnico final v1.0.0 (80 tecnicas, 171 tests, 21 comandos, REST API, Docker)
7844d6b  docs: informe profesional completo v0.5.0 (20 secciones, Fase 1 + Fase 2)
9919a88  docs: informe tecnico actualizado - Fase 2 v0.5.0 (exploitation + cleanup + state)
b9f504d  docs: update README - Fase 2 v0.5 (exploitation, cleanup, 82 tests)
4489238  chore: clean gitignore
2ffc1eb  chore: remove source code from public repo (code lives in private repo)
11739a3  docs: update README - Fase 1 completa (recon module, 50 tests)
610b4c9  chore: remove source code from public branch
0f3239a  docs: LinkedIn post RED-CORE v0.1.0
1fa2140  docs: informe tecnico completo v0.1.0
2f5e2b2  docs: add README and screenshots directory
454312a  docs: README v1.0.0 final (80 techniques, 171 tests, 21 commands, REST API, Docker)
fd5de17  docs: informe tecnico final v1.0.0 (80 tecnicas, 171 tests, 21 comandos, REST API, Docker)
7844d6b  docs: informe profesional completo v0.5.0 (20 secciones, Fase 1 + Fase 2)
9919a88  docs: informe tecnico actualizado - Fase 2 v0.5.0 (exploitation + cleanup + state)
b9f504d  docs: update README - Fase 2 v0.5 (exploitation, cleanup, 82 tests)
4489238  chore: clean gitignore
2ffc1eb  chore: remove source code from public repo (code lives in private repo)
11739a3  docs: update README - Fase 1 completa (recon module, 50 tests)
610b4c9  chore: remove source code from public branch
0f3239a  docs: LinkedIn post RED-CORE v0.1.0
1fa2140  docs: informe tecnico completo v0.1.0
2f5e2b2  docs: add README and screenshots directory


Documento emitido por HyperiumiaPatricio Tirado — CEO, Hyperiumia
hyperiumia@protonmail.com
Junio 2026


Este documento esta protegido por la cadena de evidencia SHA-256 de Hyperium RED-CORE.Cualquier alteracion al contenido puede ser detectada mediante verificacion criptografica.

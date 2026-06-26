use serde::{Deserialize, Serialize};

// --- Target & Scope ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub ip: String,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub open_ports: Vec<PortInfo>,
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
}

// --- Scope / Authorization ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub client_name: String,
    pub authorized_by: String,
    pub authorization_date: String,
    pub scope_description: String,
    pub ip_ranges: Vec<String>,
    pub excluded_ips: Vec<String>,
    pub engagement_type: String,
    pub signed_hash: String,
}

// --- Evidence ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 8,
            Severity::Critical => 10,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub id: i64,
    pub phase: String,
    pub technique_id: String,
    pub technique_name: String,
    pub target: String,
    pub target_port: Option<u16>,
    pub command: String,
    pub output_hash: String,
    pub output_snippet: String,
    pub result_summary: String,
    pub severity: Severity,
    pub prev_hash: String,
    pub chain_hash: String,
    pub timestamp: String,
    pub duration_ms: u64,
}

// --- Kill Chain ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KillChainPhase {
    Recon,
    Weaponization,
    Exploitation,
    PostExploitation,
    Persistence,
    Impact,
}

impl KillChainPhase {
    pub fn name(&self) -> &str {
        match self {
            KillChainPhase::Recon => "Reconnaissance",
            KillChainPhase::Weaponization => "Weaponization",
            KillChainPhase::Exploitation => "Exploitation",
            KillChainPhase::PostExploitation => "Post-Exploitation",
            KillChainPhase::Persistence => "Persistence",
            KillChainPhase::Impact => "Impact Analysis",
        }
    }

    pub fn ptes_phase(&self) -> &str {
        match self {
            KillChainPhase::Recon => "Intelligence Gathering",
            KillChainPhase::Weaponization => "Weaponization",
            KillChainPhase::Exploitation => "Exploitation",
            KillChainPhase::PostExploitation => "Post-Exploitation",
            KillChainPhase::Persistence => "Post-Exploitation",
            KillChainPhase::Impact => "Reporting",
        }
    }

    pub fn all() -> Vec<KillChainPhase> {
        vec![
            KillChainPhase::Recon,
            KillChainPhase::Weaponization,
            KillChainPhase::Exploitation,
            KillChainPhase::PostExploitation,
            KillChainPhase::Persistence,
            KillChainPhase::Impact,
        ]
    }
}

impl std::fmt::Display for KillChainPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// --- MITRE ATT&CK Technique ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub kill_chain_phase: String,
    pub platforms: Vec<String>,
    pub data_sources: Vec<String>,
    pub is_destructive: bool,
    pub requires_auth: bool,
    pub detection_difficulty: String,
}

// --- Impact Analysis ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub technique_ids: Vec<String>,
    pub affected_systems: Vec<String>,
    pub business_impact_description: String,
    pub financial_impact_low: f64,
    pub financial_impact_high: f64,
    pub regulatory_violations: Vec<RegulatoryViolation>,
    pub remediation: String,
    pub evidence_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryViolation {
    pub framework: String,
    pub requirement: String,
    pub description: String,
}

// --- Dictamen (Legal Report) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dictamen {
    pub id: String,
    pub client_name: String,
    pub engagement_type: String,
    pub generated_at: String,
    pub executive_summary: ExecutiveSummary,
    pub kill_chain_summary: Vec<KillChainStep>,
    pub findings: Vec<Finding>,
    pub evidence_chain_valid: bool,
    pub evidence_chain_count: usize,
    pub dictamen_hash: String,
    pub total_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub risk_level: String,
    pub financial_impact_low: f64,
    pub financial_impact_high: f64,
    pub time_to_compromise: String,
    pub kill_chain_phases_completed: u8,
    pub kill_chain_phases_total: u8,
    pub techniques_executed: usize,
    pub systems_tested: usize,
    pub systems_compromised: usize,
    pub credentials_compromised: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainStep {
    pub timestamp: String,
    pub phase: String,
    pub technique_id: String,
    pub description: String,
    pub target: String,
    pub result: String,
    pub severity: String,
}

// --- Engagement Configuration ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementConfig {
    pub client_name: String,
    pub authorized_by: String,
    pub authorization_date: String,
    pub scope: Vec<String>,
    pub excluded: Vec<String>,
    pub engagement_type: String,
    pub max_concurrent: usize,
    pub timeout_secs: u64,
    pub safe_mode: bool,
    pub phases: Vec<String>,
}

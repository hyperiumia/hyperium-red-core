use crate::types::MitreTechnique;

/// MITRE ATT&CK technique database for Red Team operations.
/// Phase 1: Core techniques for recon, exploitation, lateral movement, persistence.
pub struct MitreDatabase {
    techniques: Vec<MitreTechnique>,
}

impl MitreDatabase {
    pub fn new() -> Self {
        MitreDatabase {
            techniques: Self::load_techniques(),
        }
    }

    /// Get all techniques
    pub fn all(&self) -> &[MitreTechnique] {
        &self.techniques
    }

    /// Find technique by ID (e.g. "T1046")
    pub fn get(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.iter().find(|t| t.id == id)
    }

    /// Get techniques by tactic
    pub fn by_tactic(&self, tactic: &str) -> Vec<&MitreTechnique> {
        self.techniques.iter().filter(|t| t.tactic == tactic).collect()
    }

    /// Get techniques by kill chain phase
    pub fn by_phase(&self, phase: &str) -> Vec<&MitreTechnique> {
        self.techniques.iter().filter(|t| t.kill_chain_phase == phase).collect()
    }

    /// Get non-destructive techniques only (safe mode)
    pub fn safe_techniques(&self) -> Vec<&MitreTechnique> {
        self.techniques.iter().filter(|t| !t.is_destructive).collect()
    }

    /// Count techniques
    pub fn count(&self) -> usize {
        self.techniques.len()
    }

    /// Load the core technique database
    fn load_techniques() -> Vec<MitreTechnique> {
        vec![
            // ─── Reconnaissance ───────────────────────────────
            MitreTechnique {
                id: "T1046".into(),
                name: "Network Service Discovery".into(),
                tactic: "Discovery".into(),
                description: "Scan network to enumerate open ports and services on target systems".into(),
                kill_chain_phase: "recon".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Network traffic flow".into(), "Netflow".into()],
                is_destructive: false,
                requires_auth: false,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1018".into(),
                name: "Remote System Discovery".into(),
                tactic: "Discovery".into(),
                description: "Enumerate hosts on the network via ARP, ping sweep, or DNS".into(),
                kill_chain_phase: "recon".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["Network traffic flow".into()],
                is_destructive: false,
                requires_auth: false,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1087".into(),
                name: "Account Discovery".into(),
                tactic: "Discovery".into(),
                description: "Enumerate user accounts on local system or via Active Directory".into(),
                kill_chain_phase: "recon".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Process creation".into(), "Command execution".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1482".into(),
                name: "Domain Trust Discovery".into(),
                tactic: "Discovery".into(),
                description: "Enumerate Active Directory domain trusts".into(),
                kill_chain_phase: "recon".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Process creation".into(), "Command execution".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1592".into(),
                name: "Gather Victim Host Information".into(),
                tactic: "Reconnaissance".into(),
                description: "Gather information about victim hosts including hardware, software, and configuration".into(),
                kill_chain_phase: "recon".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["HTTP traffic".into()],
                is_destructive: false,
                requires_auth: false,
                detection_difficulty: "Hard".into(),
            },

            // ─── Initial Access / Exploitation ────────────────
            MitreTechnique {
                id: "T1190".into(),
                name: "Exploit Public-Facing Application".into(),
                tactic: "Initial Access".into(),
                description: "Exploit vulnerabilities in internet-facing applications (web servers, VPN, RDP)".into(),
                kill_chain_phase: "exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Application logs".into(), "Network traffic".into()],
                is_destructive: false,
                requires_auth: false,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1078".into(),
                name: "Valid Accounts".into(),
                tactic: "Initial Access".into(),
                description: "Use stolen or default credentials to gain initial access".into(),
                kill_chain_phase: "exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Authentication logs".into()],
                is_destructive: false,
                requires_auth: false,
                detection_difficulty: "Hard".into(),
            },
            MitreTechnique {
                id: "T1110".into(),
                name: "Brute Force".into(),
                tactic: "Credential Access".into(),
                description: "Brute force passwords against exposed services (SSH, RDP, SMB, web login)".into(),
                kill_chain_phase: "exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Authentication logs".into()],
                is_destructive: false,
                requires_auth: false,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1210".into(),
                name: "Exploitation of Remote Services".into(),
                tactic: "Lateral Movement".into(),
                description: "Exploit vulnerabilities in remote services for lateral movement".into(),
                kill_chain_phase: "exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["Network traffic".into(), "Process creation".into()],
                is_destructive: false,
                requires_auth: false,
                detection_difficulty: "Medium".into(),
            },

            // ─── Execution ────────────────────────────────────
            MitreTechnique {
                id: "T1059".into(),
                name: "Command and Scripting Interpreter".into(),
                tactic: "Execution".into(),
                description: "Execute commands via shell, PowerShell, Python, or other interpreters".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Process creation".into(), "Command execution".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },

            // ─── Privilege Escalation ─────────────────────────
            MitreTechnique {
                id: "T1068".into(),
                name: "Exploitation for Privilege Escalation".into(),
                tactic: "Privilege Escalation".into(),
                description: "Exploit software vulnerabilities to escalate privileges (kernel exploits, misconfigs)".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["Process creation".into(), "File monitoring".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Hard".into(),
            },
            MitreTechnique {
                id: "T1548".into(),
                name: "Abuse Elevation Control Mechanism".into(),
                tactic: "Privilege Escalation".into(),
                description: "Bypass UAC, Sudo, or other elevation controls".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Process creation".into(), "Command execution".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },

            // ─── Credential Access ────────────────────────────
            MitreTechnique {
                id: "T1003".into(),
                name: "OS Credential Dumping".into(),
                tactic: "Credential Access".into(),
                description: "Dump credentials from OS stores (LSASS, SAM, /etc/shadow, keychains)".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["Process access".into(), "File monitoring".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1003.001".into(),
                name: "LSASS Memory".into(),
                tactic: "Credential Access".into(),
                description: "Dump credentials from LSASS process memory (Mimikatz, comsvcs.dll)".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Process access".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1558".into(),
                name: "Steal or Forge Kerberos Tickets".into(),
                tactic: "Credential Access".into(),
                description: "Kerberoasting, AS-REP roasting, and other Kerberos attacks".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Authentication logs".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1110.002".into(),
                name: "Password Cracking".into(),
                tactic: "Credential Access".into(),
                description: "Offline cracking of captured password hashes".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["File monitoring".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Hard".into(),
            },

            // ─── Lateral Movement ─────────────────────────────
            MitreTechnique {
                id: "T1021.002".into(),
                name: "SMB/Windows Admin Shares".into(),
                tactic: "Lateral Movement".into(),
                description: "Move laterally via SMB admin shares (ADMIN$, C$, IPC$)".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Network traffic".into(), "Authentication logs".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1021.001".into(),
                name: "Remote Desktop Protocol".into(),
                tactic: "Lateral Movement".into(),
                description: "Move laterally via RDP with harvested credentials".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Network traffic".into(), "Authentication logs".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1550.002".into(),
                name: "Pass the Hash".into(),
                tactic: "Lateral Movement".into(),
                description: "Authenticate using NTLM password hashes without knowing the plaintext".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Authentication logs".into(), "Network traffic".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Hard".into(),
            },
            MitreTechnique {
                id: "T1021.003".into(),
                name: "Distributed Component Object Model".into(),
                tactic: "Lateral Movement".into(),
                description: "Lateral movement via DCOM".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Network traffic".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Hard".into(),
            },

            // ─── Persistence ──────────────────────────────────
            MitreTechnique {
                id: "T1053.005".into(),
                name: "Scheduled Task".into(),
                tactic: "Persistence".into(),
                description: "Create scheduled tasks for persistence".into(),
                kill_chain_phase: "persistence".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["File monitoring".into(), "Process creation".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1543.003".into(),
                name: "Windows Service".into(),
                tactic: "Persistence".into(),
                description: "Create or modify Windows services for persistence".into(),
                kill_chain_phase: "persistence".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Service creation".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1136".into(),
                name: "Create Account".into(),
                tactic: "Persistence".into(),
                description: "Create new user accounts for persistent access".into(),
                kill_chain_phase: "persistence".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["Authentication logs".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1547.001".into(),
                name: "Registry Run Keys".into(),
                tactic: "Persistence".into(),
                description: "Add entries to Registry Run keys for persistence".into(),
                kill_chain_phase: "persistence".into(),
                platforms: vec!["Windows".into()],
                data_sources: vec!["Registry monitoring".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1505.003".into(),
                name: "Web Shell".into(),
                tactic: "Persistence".into(),
                description: "Deploy web shells on compromised web servers".into(),
                kill_chain_phase: "persistence".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["File monitoring".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },

            // ─── Defense Evasion ──────────────────────────────
            MitreTechnique {
                id: "T1070".into(),
                name: "Indicator Removal".into(),
                tactic: "Defense Evasion".into(),
                description: "Clear logs and indicators of compromise".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["Log monitoring".into()],
                is_destructive: true,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },

            // ─── Collection / Exfiltration ────────────────────
            MitreTechnique {
                id: "T1005".into(),
                name: "Data from Local System".into(),
                tactic: "Collection".into(),
                description: "Search and collect sensitive data from local file systems".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
                data_sources: vec!["File monitoring".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1039".into(),
                name: "Data from Network Shared Drive".into(),
                tactic: "Collection".into(),
                description: "Collect data from network shares and mapped drives".into(),
                kill_chain_phase: "post_exploitation".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["File monitoring".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Medium".into(),
            },
            MitreTechnique {
                id: "T1041".into(),
                name: "Exfiltration Over C2 Channel".into(),
                tactic: "Exfiltration".into(),
                description: "Simulate data exfiltration over command and control channel".into(),
                kill_chain_phase: "impact".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["Network traffic".into()],
                is_destructive: false,
                requires_auth: true,
                detection_difficulty: "Hard".into(),
            },

            // ─── Impact (non-destructive assessment only) ─────
            MitreTechnique {
                id: "T1486".into(),
                name: "Data Encrypted for Impact".into(),
                tactic: "Impact".into(),
                description: "ASSESS ONLY: Document if ransomware deployment is possible (never execute)".into(),
                kill_chain_phase: "impact".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["File monitoring".into()],
                is_destructive: true,
                requires_auth: true,
                detection_difficulty: "Easy".into(),
            },
            MitreTechnique {
                id: "T1489".into(),
                name: "Service Stop".into(),
                tactic: "Impact".into(),
                description: "ASSESS ONLY: Document if critical services can be stopped (never execute)".into(),
                kill_chain_phase: "impact".into(),
                platforms: vec!["Windows".into(), "Linux".into()],
                data_sources: vec!["Service monitoring".into()],
                is_destructive: true,
                requires_auth: true,
                detection_difficulty: "Easy".into(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_count() {
        let db = MitreDatabase::new();
        assert!(db.count() >= 30, "Expected at least 30 techniques, got {}", db.count());
    }

    #[test]
    fn test_get_by_id() {
        let db = MitreDatabase::new();
        let t = db.get("T1046").unwrap();
        assert_eq!(t.name, "Network Service Discovery");
        assert_eq!(t.tactic, "Discovery");
    }

    #[test]
    fn test_get_nonexistent() {
        let db = MitreDatabase::new();
        assert!(db.get("T9999").is_none());
    }

    #[test]
    fn test_by_tactic() {
        let db = MitreDatabase::new();
        let discovery = db.by_tactic("Discovery");
        assert!(discovery.len() >= 3);
        for t in &discovery {
            assert_eq!(t.tactic, "Discovery");
        }
    }

    #[test]
    fn test_by_phase() {
        let db = MitreDatabase::new();
        let recon = db.by_phase("recon");
        assert!(recon.len() >= 3);
        let exploit = db.by_phase("exploitation");
        assert!(exploit.len() >= 2);
        let persist = db.by_phase("persistence");
        assert!(persist.len() >= 3);
    }

    #[test]
    fn test_safe_techniques() {
        let db = MitreDatabase::new();
        let safe = db.safe_techniques();
        for t in &safe {
            assert!(!t.is_destructive, "{} should not be destructive", t.id);
        }
        // Safe techniques should be the majority
        assert!(safe.len() > db.count() / 2);
    }

    #[test]
    fn test_all_techniques_have_ids() {
        let db = MitreDatabase::new();
        for t in db.all() {
            assert!(t.id.starts_with('T'), "Technique ID should start with T: {}", t.id);
            assert!(!t.name.is_empty());
            assert!(!t.tactic.is_empty());
            assert!(!t.kill_chain_phase.is_empty());
        }
    }

    #[test]
    fn test_all_platforms_covered() {
        let db = MitreDatabase::new();
        let all_techniques = db.all();
        let has_windows = all_techniques.iter().any(|t| t.platforms.contains(&"Windows".to_string()));
        let has_linux = all_techniques.iter().any(|t| t.platforms.contains(&"Linux".to_string()));
        assert!(has_windows);
        assert!(has_linux);
    }

    #[test]
    fn test_killer_chain_coverage() {
        let db = MitreDatabase::new();
        let phases = vec!["recon", "exploitation", "post_exploitation", "persistence", "impact"];
        for phase in phases {
            let techniques = db.by_phase(phase);
            assert!(!techniques.is_empty(), "Phase '{}' should have at least 1 technique", phase);
        }
    }
}

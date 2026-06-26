use crate::types::RegulatoryViolation;

/// Compliance framework mapping for Red Team findings.
/// Maps MITRE ATT&CK techniques to regulatory requirements.
pub struct ComplianceMapper;

impl ComplianceMapper {
    /// Get all regulatory violations for a given technique
    pub fn map_technique(technique_id: &str) -> Vec<RegulatoryViolation> {
        match technique_id {
            // Initial Access / Exploitation
            "T1190" => vec![
                v("PCI DSS 4.0", "6.2.4", "Software engineering techniques to prevent common attacks"),
                v("PCI DSS 4.0", "11.3.1", "Penetration testing methodology"),
                v("NIST SP 800-53", "SI-2", "Flaw remediation"),
                v("NIS2", "Art. 21(1)", "Risk management measures"),
                v("GDPR", "Art. 32", "Security of processing"),
            ],

            // Credential Access
            "T1003" | "T1003.001" => vec![
                v("PCI DSS 4.0", "8.3.1", "Strong authentication for administrative access"),
                v("GDPR", "Art. 32", "Appropriate technical measures"),
                v("NIST 800-63B", "5.1.1", "Memorized secret verifiers"),
                v("HIPAA", "164.312(a)(1)", "Access control"),
                v("SOC 2", "CC6.1", "Logical access security"),
            ],
            "T1558" => vec![
                v("PCI DSS 4.0", "8.3.1", "Multi-factor authentication"),
                v("NIST SP 800-53", "IA-2", "Identification and authentication"),
                v("SOC 2", "CC6.1", "Logical access security"),
            ],
            "T1110" | "T1110.002" => vec![
                v("PCI DSS 4.0", "8.3.1", "Multi-factor authentication for administrative access"),
                v("NIST SP 800-53", "IA-5", "Authenticator management"),
            ],

            // Lateral Movement
            "T1550.002" | "T1021.002" | "T1021.001" | "T1021.003" => vec![
                v("PCI DSS 4.0", "3.4", "Render PAN unreadable"),
                v("SOC 2", "CC6.1", "Logical access security"),
                v("GDPR", "Art. 32", "Security of processing"),
                v("HIPAA", "164.312(e)(1)", "Transmission security"),
            ],
            "T1210" => vec![
                v("PCI DSS 4.0", "11.3", "Penetration testing"),
                v("NIST SP 800-53", "CA-8", "Penetration testing"),
                v("NIS2", "Art. 21", "Risk management"),
            ],

            // Privilege Escalation
            "T1068" => vec![
                v("PCI DSS 4.0", "7.2.1", "Access control systems deny all by default"),
                v("NIST SP 800-53", "AC-6", "Least privilege"),
                v("SOC 2", "CC6.2", "Prior to issuing system credentials"),
            ],
            "T1548" => vec![
                v("PCI DSS 4.0", "7.2.1", "Least privilege"),
                v("NIST SP 800-53", "AC-6(1)", "Authorize access to security functions"),
            ],

            // Persistence
            "T1053.005" | "T1543.003" | "T1136" | "T1547.001" | "T1505.003" => vec![
                v("NIST SP 800-53", "SI-4", "System monitoring"),
                v("SOC 2", "CC7.2", "Monitoring for anomalies"),
                v("PCI DSS 4.0", "10.4", "Audit logs reviewed promptly"),
                v("HIPAA", "164.312(b)", "Audit controls"),
            ],

            // Defense Evasion
            "T1070" => vec![
                v("PCI DSS 4.0", "10.5", "Retain audit log history"),
                v("SOC 2", "CC7.2", "Monitoring"),
                v("NIST SP 800-92", "2.1", "Log management"),
            ],

            // Destructive
            "T1486" => vec![
                v("PCI DSS 4.0", "12.10", "Incident response plan"),
                v("NIS2", "Art. 21", "Risk management measures"),
                v("NIS2", "Art. 23", "Incident reporting"),
                v("GDPR", "Art. 33", "Notification of breach (72h)"),
                v("HIPAA", "164.308(a)(6)", "Security incident procedures"),
            ],
            "T1489" => vec![
                v("PCI DSS 4.0", "12.10", "Incident response plan"),
                v("SOC 2", "CC7.4", "Response to security incidents"),
            ],

            // Collection / Exfiltration
            "T1005" | "T1039" => vec![
                v("PCI DSS 4.0", "3.4", "Protect stored cardholder data"),
                v("GDPR", "Art. 5(1)(f)", "Integrity and confidentiality"),
                v("HIPAA", "164.312(a)(1", "Access control"),
            ],
            "T1041" => vec![
                v("PCI DSS 4.0", "11.3", "Penetration testing"),
                v("GDPR", "Art. 33", "Breach notification"),
                v("NIS2", "Art. 23", "Incident reporting"),
            ],

            // Default
            _ => vec![],
        }
    }

    /// Get PTES phase for a kill chain phase
    pub fn ptes_mapping(kill_chain_phase: &str) -> &str {
        match kill_chain_phase {
            "recon" => "Intelligence Gathering",
            "weaponization" => "Weaponization",
            "exploitation" => "Exploitation",
            "post_exploitation" => "Post-Exploitation",
            "persistence" => "Post-Exploitation",
            "impact" => "Reporting",
            _ => "Unknown",
        }
    }

    /// Get all frameworks used
    pub fn frameworks() -> Vec<&'static str> {
        vec![
            "PCI DSS 4.0",
            "GDPR",
            "NIST SP 800-53",
            "NIST 800-63B",
            "NIST SP 800-92",
            "HIPAA",
            "SOC 2",
            "NIS2",
            "PTES",
        ]
    }
}

fn v(framework: &str, requirement: &str, description: &str) -> RegulatoryViolation {
    RegulatoryViolation {
        framework: framework.to_string(),
        requirement: requirement.to_string(),
        description: description.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exploit_technique_has_pci() {
        let violations = ComplianceMapper::map_technique("T1190");
        assert!(!violations.is_empty());
        let pci: Vec<_> = violations.iter().filter(|v| v.framework.contains("PCI")).collect();
        assert!(!pci.is_empty(), "T1190 should have PCI DSS violations");
    }

    #[test]
    fn test_credential_dump_has_multiple_frameworks() {
        let violations = ComplianceMapper::map_technique("T1003.001");
        let frameworks: Vec<&str> = violations.iter().map(|v| v.framework.as_str()).collect();
        assert!(frameworks.contains(&"PCI DSS 4.0"));
        assert!(frameworks.contains(&"GDPR"));
        assert!(frameworks.contains(&"HIPAA"));
        assert!(frameworks.contains(&"SOC 2"));
    }

    #[test]
    fn test_ransomware_has_nis2() {
        let violations = ComplianceMapper::map_technique("T1486");
        let nis2: Vec<_> = violations.iter().filter(|v| v.framework.contains("NIS2")).collect();
        assert!(!nis2.is_empty(), "T1486 should have NIS2 violations");
    }

    #[test]
    fn test_unknown_technique_returns_empty() {
        let violations = ComplianceMapper::map_technique("T9999");
        assert!(violations.is_empty());
    }

    #[test]
    fn test_ptes_mapping() {
        assert_eq!(ComplianceMapper::ptes_mapping("recon"), "Intelligence Gathering");
        assert_eq!(ComplianceMapper::ptes_mapping("exploitation"), "Exploitation");
        assert_eq!(ComplianceMapper::ptes_mapping("impact"), "Reporting");
    }

    #[test]
    fn test_frameworks_list() {
        let frameworks = ComplianceMapper::frameworks();
        assert!(frameworks.len() >= 8);
        assert!(frameworks.contains(&"PCI DSS 4.0"));
        assert!(frameworks.contains(&"GDPR"));
        assert!(frameworks.contains(&"PTES"));
    }

    #[test]
    fn test_lateral_movement_compliance() {
        let violations = ComplianceMapper::map_technique("T1550.002");
        assert!(violations.len() >= 3);
        let frameworks: Vec<&str> = violations.iter().map(|v| v.framework.as_str()).collect();
        assert!(frameworks.contains(&"SOC 2"));
    }
}

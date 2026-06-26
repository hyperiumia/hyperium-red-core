use crate::types::{Finding, Severity, RegulatoryViolation, Target};
use crate::evidence::EvidenceChain;

/// Business impact calculation engine.
/// Maps technical findings to financial impact and regulatory violations.
pub struct ImpactEngine;

impl ImpactEngine {
    /// Calculate business impact from evidence chain and discovered targets
    pub fn analyze(evidence: &EvidenceChain, targets: &[Target]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Analyze each critical/high severity evidence entry
        for entry in evidence.entries() {
            match entry.technique_id.as_str() {
                "T1190" | "T1210" => {
                    findings.push(Self::finding_initial_access(entry));
                }
                "T1003" | "T1003.001" | "T1558" | "T1110.002" => {
                    findings.push(Self::finding_credential_dump(entry));
                }
                "T1550.002" | "T1021.002" | "T1021.001" => {
                    findings.push(Self::finding_lateral_movement(entry));
                }
                "T1068" | "T1548" => {
                    findings.push(Self::finding_priv_escalation(entry));
                }
                "T1053.005" | "T1543.003" | "T1136" | "T1547.001" | "T1505.003" => {
                    findings.push(Self::finding_persistence(entry));
                }
                "T1486" | "T1489" => {
                    findings.push(Self::finding_destructive(entry));
                }
                _ => {}
            }
        }

        // Generate summary finding if multiple critical issues
        let critical_count = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
        if critical_count >= 2 {
            findings.push(Self::finding_chain_compromise(&findings, targets));
        }

        findings
    }

    fn finding_initial_access(entry: &crate::types::EvidenceEntry) -> Finding {
        Finding {
            id: format!("FIND-{}", entry.id),
            title: format!("Remote Code Execution via {}", entry.technique_name),
            description: format!(
                "Attacker can achieve initial access to {}:{} using {}. {}",
                entry.target, entry.target_port.unwrap_or(0), entry.technique_name, entry.result_summary
            ),
            severity: Severity::Critical,
            technique_ids: vec![entry.technique_id.clone()],
            affected_systems: vec![entry.target.clone()],
            business_impact_description: "Initial access allows attacker to enter the network. From this foothold, lateral movement, data exfiltration, and ransomware deployment become possible.".into(),
            financial_impact_low: 200_000.0,
            financial_impact_high: 2_100_000.0,
            regulatory_violations: vec![
                RegulatoryViolation {
                    framework: "PCI DSS 4.0".into(),
                    requirement: "6.2.4".into(),
                    description: "Software engineering techniques must prevent common software attacks".into(),
                },
                RegulatoryViolation {
                    framework: "NIST SP 800-53".into(),
                    requirement: "SI-2".into(),
                    description: "Flaw remediation must be timely".into(),
                },
            ],
            remediation: "Apply security patches promptly. Implement Web Application Firewall. Conduct regular vulnerability scanning.".into(),
            evidence_ids: vec![entry.id],
        }
    }

    fn finding_credential_dump(entry: &crate::types::EvidenceEntry) -> Finding {
        Finding {
            id: format!("FIND-{}", entry.id),
            title: format!("Credential Harvesting via {}", entry.technique_name),
            description: format!(
                "Attacker can extract credentials from {} using {}. {}",
                entry.target, entry.technique_name, entry.result_summary
            ),
            severity: Severity::Critical,
            technique_ids: vec![entry.technique_id.clone()],
            affected_systems: vec![entry.target.clone()],
            business_impact_description: "Credential harvesting enables lateral movement across the entire network. Compromised credentials can be used for months without detection if not rotated.".into(),
            financial_impact_low: 800_000.0,
            financial_impact_high: 5_400_000.0,
            regulatory_violations: vec![
                RegulatoryViolation {
                    framework: "GDPR".into(),
                    requirement: "Art. 32".into(),
                    description: "Appropriate technical measures to ensure security of processing".into(),
                },
                RegulatoryViolation {
                    framework: "PCI DSS 4.0".into(),
                    requirement: "8.3.1".into(),
                    description: "Strong authentication for administrative access".into(),
                },
                RegulatoryViolation {
                    framework: "NIST 800-63B".into(),
                    requirement: "5.1.1".into(),
                    description: "Memorized secret verifiers must be salted and hashed".into(),
                },
            ],
            remediation: "Implement LAPS (Local Administrator Password Solution). Deploy credential tiering. Enable Credential Guard on Windows. Monitor LSASS access.".into(),
            evidence_ids: vec![entry.id],
        }
    }

    fn finding_lateral_movement(entry: &crate::types::EvidenceEntry) -> Finding {
        Finding {
            id: format!("FIND-{}", entry.id),
            title: format!("Lateral Movement via {}", entry.technique_name),
            description: format!(
                "Attacker can move laterally to {} using {}. {}",
                entry.target, entry.technique_name, entry.result_summary
            ),
            severity: Severity::Critical,
            technique_ids: vec![entry.technique_id.clone()],
            affected_systems: vec![entry.target.clone()],
            business_impact_description: "Lateral movement means the attacker is not contained to a single system. Every system reachable from the compromised host is at risk.".into(),
            financial_impact_low: 2_100_000.0,
            financial_impact_high: 12_800_000.0,
            regulatory_violations: vec![
                RegulatoryViolation {
                    framework: "PCI DSS 4.0".into(),
                    requirement: "3.4".into(),
                    description: "Render PAN unreadable anywhere it is stored".into(),
                },
                RegulatoryViolation {
                    framework: "SOC 2".into(),
                    requirement: "CC6.1".into(),
                    description: "Logical access security over protected information".into(),
                },
            ],
            remediation: "Implement network segmentation. Deploy privileged access workstations. Enforce MFA for lateral protocols. Monitor SMB/RDP traffic.".into(),
            evidence_ids: vec![entry.id],
        }
    }

    fn finding_priv_escalation(entry: &crate::types::EvidenceEntry) -> Finding {
        Finding {
            id: format!("FIND-{}", entry.id),
            title: format!("Privilege Escalation via {}", entry.technique_name),
            description: format!(
                "Attacker can escalate to root/SYSTEM on {}. {}",
                entry.target, entry.result_summary
            ),
            severity: Severity::Critical,
            technique_ids: vec![entry.technique_id.clone()],
            affected_systems: vec![entry.target.clone()],
            business_impact_description: "Full administrative access means the attacker controls the system completely: install malware, access all data, disable security controls, and cover tracks.".into(),
            financial_impact_low: 500_000.0,
            financial_impact_high: 4_200_000.0,
            regulatory_violations: vec![
                RegulatoryViolation {
                    framework: "PCI DSS 4.0".into(),
                    requirement: "7.2.1".into(),
                    description: "Access control systems must deny all access by default".into(),
                },
            ],
            remediation: "Apply OS patches. Implement least privilege. Deploy application whitelisting. Monitor privilege escalation events.".into(),
            evidence_ids: vec![entry.id],
        }
    }

    fn finding_persistence(entry: &crate::types::EvidenceEntry) -> Finding {
        Finding {
            id: format!("FIND-{}", entry.id),
            title: format!("Persistence Mechanism: {}", entry.technique_name),
            description: format!(
                "Attacker can establish persistent access on {}. {}",
                entry.target, entry.result_summary
            ),
            severity: Severity::High,
            technique_ids: vec![entry.technique_id.clone()],
            affected_systems: vec![entry.target.clone()],
            business_impact_description: "Persistence means the attacker can return even after the initial vulnerability is patched. Without detection, access can last months or years.".into(),
            financial_impact_low: 300_000.0,
            financial_impact_high: 2_500_000.0,
            regulatory_violations: vec![
                RegulatoryViolation {
                    framework: "NIST SP 800-53".into(),
                    requirement: "SI-4".into(),
                    description: "System monitoring to detect unauthorized persistence".into(),
                },
                RegulatoryViolation {
                    framework: "SOC 2".into(),
                    requirement: "CC7.2".into(),
                    description: "Monitoring of system components for anomalies".into(),
                },
            ],
            remediation: "Implement application whitelisting. Monitor scheduled task creation. Audit service installations. Deploy EDR with persistence detection.".into(),
            evidence_ids: vec![entry.id],
        }
    }

    fn finding_destructive(entry: &crate::types::EvidenceEntry) -> Finding {
        Finding {
            id: format!("FIND-{}", entry.id),
            title: format!("Destructive Capability Assessed: {}", entry.technique_name),
            description: format!(
                "Attacker has the capability to execute {} against {}. Assessment only — not executed. {}",
                entry.technique_name, entry.target, entry.result_summary
            ),
            severity: Severity::Critical,
            technique_ids: vec![entry.technique_id.clone()],
            affected_systems: vec![entry.target.clone()],
            business_impact_description: "Destructive capabilities (ransomware, service disruption) represent total business continuity risk. Recovery time from ransomware: average 22 days.".into(),
            financial_impact_low: 4_200_000.0,
            financial_impact_high: 12_800_000.0,
            regulatory_violations: vec![
                RegulatoryViolation {
                    framework: "NIS2".into(),
                    requirement: "Art. 21".into(),
                    description: "Risk management measures for network and information systems".into(),
                },
                RegulatoryViolation {
                    framework: "PCI DSS 4.0".into(),
                    requirement: "12.10".into(),
                    description: "Incident response plan must be in place".into(),
                },
            ],
            remediation: "Implement offline backup strategy. Deploy anti-ransomware controls. Test incident response plan. Segment critical systems.".into(),
            evidence_ids: vec![entry.id],
        }
    }

    fn finding_chain_compromise(findings: &[Finding], targets: &[Target]) -> Finding {
        let affected: Vec<String> = targets.iter().map(|t| t.ip.clone()).collect();
        let total_low: f64 = findings.iter().map(|f| f.financial_impact_low).sum();
        let total_high: f64 = findings.iter().map(|f| f.financial_impact_high).sum();
        let technique_ids: Vec<String> = findings.iter().flat_map(|f| f.technique_ids.clone()).collect();
        let evidence_ids: Vec<i64> = findings.iter().flat_map(|f| f.evidence_ids.clone()).collect();

        Finding {
            id: "FIND-CHAIN-001".into(),
            title: "Complete Kill Chain Compromise Demonstrated".into(),
            description: format!(
                "Full attack chain executed from initial access to domain compromise. {} critical findings across {} systems.",
                findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count(),
                affected.len()
            ),
            severity: Severity::Critical,
            technique_ids,
            affected_systems: affected,
            business_impact_description: "A complete kill chain compromise means an attacker can replicate this attack at any time. The organization's entire digital infrastructure is at risk. Board-level notification recommended.".into(),
            financial_impact_low: total_low,
            financial_impact_high: total_high,
            regulatory_violations: vec![
                RegulatoryViolation {
                    framework: "Multiple".into(),
                    requirement: "Multiple".into(),
                    description: "Full compromise triggers reporting obligations under GDPR (72h), PCI DSS, and NIS2".into(),
                },
            ],
            remediation: "Immediate: Patch all identified vulnerabilities. Rotate all credentials. Implement network segmentation. Long-term: Deploy Zero Trust architecture. Implement continuous security validation.".into(),
            evidence_ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    use crate::evidence::EvidenceChain;

    fn sample_evidence() -> EvidenceChain {
        let mut chain = EvidenceChain::new();
        chain.seal("exploit", "T1190", "Exploit Public-Facing Application",
            "10.0.0.1", Some(443), "CVE-2024-1234",
            "Shell obtained as SYSTEM", "Remote code execution on web server",
            Severity::Critical, 3200);
        chain.seal("post_exploitation", "T1003.001", "LSASS Memory",
            "10.0.0.1", None, "mimikatz",
            "342 hashes dumped", "Credential harvesting from LSASS",
            Severity::Critical, 5000);
        chain.seal("post_exploitation", "T1550.002", "Pass the Hash",
            "10.0.0.50", None, "psexec -hashes :NTLM",
            "Access to DC obtained", "Domain controller compromised via PtH",
            Severity::Critical, 2100);
        chain
    }

    #[test]
    fn test_impact_analysis_generates_findings() {
        let evidence = sample_evidence();
        let targets = vec![];
        let findings = ImpactEngine::analyze(&evidence, &targets);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_critical_findings_for_exploit() {
        let evidence = sample_evidence();
        let findings = ImpactEngine::analyze(&evidence, &vec![]);
        let exploit_finding = findings.iter().find(|f| f.technique_ids.contains(&"T1190".to_string()));
        assert!(exploit_finding.is_some());
        let f = exploit_finding.unwrap();
        assert!(matches!(f.severity, Severity::Critical));
        assert!(f.financial_impact_low > 0.0);
        assert!(f.financial_impact_high > f.financial_impact_low);
    }

    #[test]
    fn test_credential_finding_has_regulatory_violations() {
        let evidence = sample_evidence();
        let findings = ImpactEngine::analyze(&evidence, &vec![]);
        let cred_finding = findings.iter().find(|f| f.technique_ids.contains(&"T1003.001".to_string()));
        assert!(cred_finding.is_some());
        let f = cred_finding.unwrap();
        assert!(f.regulatory_violations.len() >= 2);
        let frameworks: Vec<&str> = f.regulatory_violations.iter().map(|v| v.framework.as_str()).collect();
        assert!(frameworks.contains(&"PCI DSS 4.0"));
    }

    #[test]
    fn test_chain_compromise_finding() {
        let evidence = sample_evidence();
        let targets = vec![
            Target { ip: "10.0.0.1".into(), hostname: None, os_guess: None, open_ports: vec![], services: vec![] },
            Target { ip: "10.0.0.50".into(), hostname: None, os_guess: None, open_ports: vec![], services: vec![] },
        ];
        let findings = ImpactEngine::analyze(&evidence, &targets);
        let chain_finding = findings.iter().find(|f| f.id == "FIND-CHAIN-001");
        assert!(chain_finding.is_some(), "Should have chain compromise finding when >= 2 critical");
    }

    #[test]
    fn test_no_chain_compromise_with_single_critical() {
        let mut evidence = EvidenceChain::new();
        evidence.seal("exploit", "T1190", "Exploit", "10.0.0.1", Some(443),
            "cmd", "output", "result", Severity::Critical, 100);
        let findings = ImpactEngine::analyze(&evidence, &vec![]);
        let chain_finding = findings.iter().find(|f| f.id == "FIND-CHAIN-001");
        assert!(chain_finding.is_none(), "Should not have chain compromise with single critical");
    }

    #[test]
    fn test_financial_impacts_are_positive() {
        let evidence = sample_evidence();
        let findings = ImpactEngine::analyze(&evidence, &vec![]);
        for f in &findings {
            assert!(f.financial_impact_low >= 0.0, "{}: low impact should be >= 0", f.id);
            assert!(f.financial_impact_high >= f.financial_impact_low, "{}: high >= low", f.id);
        }
    }

    #[test]
    fn test_remediation_not_empty() {
        let evidence = sample_evidence();
        let findings = ImpactEngine::analyze(&evidence, &vec![]);
        for f in &findings {
            assert!(!f.remediation.is_empty(), "{}: remediation should not be empty", f.id);
        }
    }
}

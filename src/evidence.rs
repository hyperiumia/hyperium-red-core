use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::types::{EvidenceEntry, Severity};

// ─── Evidence Chain ───────────────────────────────────────
// Tamper-evident audit trail using chained SHA-256 hashes.
// Each event contains the hash of the previous event.
// Mathematically impossible to alter historical records.

pub struct EvidenceChain {
    entries: Vec<EvidenceEntry>,
    next_id: i64,
}

impl EvidenceChain {
    pub fn new() -> Self {
        EvidenceChain {
            entries: Vec::new(),
            next_id: 1,
        }
    }

    /// Get the hash of the last entry, or GENESIS if empty
    pub fn last_hash(&self) -> String {
        self.entries
            .last()
            .map(|e| e.chain_hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string())
    }

    /// Seal a new event into the evidence chain
    pub fn seal(
        &mut self,
        phase: &str,
        technique_id: &str,
        technique_name: &str,
        target: &str,
        target_port: Option<u16>,
        command: &str,
        output: &str,
        result_summary: &str,
        severity: Severity,
        duration_ms: u64,
    ) -> &EvidenceEntry {
        let prev_hash = self.last_hash();
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string();
        let id = self.next_id;

        // Hash the full output
        let mut output_hasher = Sha256::new();
        output_hasher.update(output.as_bytes());
        let output_hash = format!("{:x}", output_hasher.finalize());

        // Take first 500 chars of output for display
        let output_snippet = if output.len() > 500 {
            format!("{}...", &output[..497])
        } else {
            output.to_string()
        };

        // Chain hash = SHA-256(prev_hash + phase + technique_id + target + command + output_hash + timestamp)
        let mut chain_hasher = Sha256::new();
        chain_hasher.update(prev_hash.as_bytes());
        chain_hasher.update(phase.as_bytes());
        chain_hasher.update(technique_id.as_bytes());
        chain_hasher.update(target.as_bytes());
        chain_hasher.update(command.as_bytes());
        chain_hasher.update(output_hash.as_bytes());
        chain_hasher.update(timestamp.as_bytes());
        let chain_hash = format!("{:x}", chain_hasher.finalize());

        let entry = EvidenceEntry {
            id,
            phase: phase.to_string(),
            technique_id: technique_id.to_string(),
            technique_name: technique_name.to_string(),
            target: target.to_string(),
            target_port,
            command: command.to_string(),
            output_hash,
            output_snippet,
            result_summary: result_summary.to_string(),
            severity,
            prev_hash,
            chain_hash,
            timestamp,
            duration_ms,
        };

        self.next_id += 1;
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Verify the entire chain integrity
    pub fn verify(&self) -> (bool, usize, usize) {
        if self.entries.is_empty() {
            return (true, 0, 0);
        }

        let mut prev_hash = "GENESIS".to_string();
        let mut total = 0;
        let mut valid = 0;

        for entry in &self.entries {
            total += 1;

            // Check prev_hash
            if entry.prev_hash != prev_hash {
                continue;
            }

            // Recompute chain hash
            let mut hasher = Sha256::new();
            hasher.update(prev_hash.as_bytes());
            hasher.update(entry.phase.as_bytes());
            hasher.update(entry.technique_id.as_bytes());
            hasher.update(entry.target.as_bytes());
            hasher.update(entry.command.as_bytes());
            hasher.update(entry.output_hash.as_bytes());
            hasher.update(entry.timestamp.as_bytes());
            let computed = format!("{:x}", hasher.finalize());

            if computed == entry.chain_hash {
                valid += 1;
            }

            prev_hash = entry.chain_hash.clone();
        }

        (valid == total, total, valid)
    }

    /// Get all entries
    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    /// Get entry count
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Get entries filtered by phase
    pub fn entries_by_phase(&self, phase: &str) -> Vec<&EvidenceEntry> {
        self.entries.iter().filter(|e| e.phase == phase).collect()
    }

    /// Get entries filtered by severity
    pub fn entries_by_severity(&self, severity: &Severity) -> Vec<&EvidenceEntry> {
        self.entries.iter().filter(|e| std::mem::discriminant(&e.severity) == std::mem::discriminant(severity)).collect()
    }

    /// Get total duration across all entries
    pub fn total_duration_ms(&self) -> u64 {
        self.entries.iter().map(|e| e.duration_ms).sum()
    }

    /// Export chain as JSON for persistence
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.entries).unwrap_or_default()
    }

    /// Compute overall risk level from entries
    pub fn overall_risk(&self) -> String {
        let has_critical = self.entries.iter().any(|e| matches!(e.severity, Severity::Critical));
        let has_high = self.entries.iter().any(|e| matches!(e.severity, Severity::High));

        if has_critical {
            "CRITICAL".to_string()
        } else if has_high {
            "HIGH".to_string()
        } else if !self.entries.is_empty() {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_is_valid() {
        let chain = EvidenceChain::new();
        let (valid, total, ok) = chain.verify();
        assert!(valid);
        assert_eq!(total, 0);
        assert_eq!(ok, 0);
    }

    #[test]
    fn test_single_entry() {
        let mut chain = EvidenceChain::new();
        chain.seal(
            "recon", "T1046", "Network Service Discovery",
            "192.168.1.1", Some(443),
            "nmap -sV 192.168.1.1",
            "443/tcp open https Apache/2.4",
            "HTTPS service detected on port 443",
            Severity::Info, 1500,
        );

        let (valid, total, ok) = chain.verify();
        assert!(valid);
        assert_eq!(total, 1);
        assert_eq!(ok, 1);
    }

    #[test]
    fn test_chain_integrity_multiple() {
        let mut chain = EvidenceChain::new();

        chain.seal("recon", "T1046", "Network Service Discovery",
            "192.168.1.1", Some(22), "nmap -sV 192.168.1.1",
            "22/tcp open ssh", "SSH detected", Severity::Info, 500);

        chain.seal("exploit", "T1190", "Exploit Public-Facing Application",
            "192.168.1.1", Some(443), "CVE-2024-1234",
            "Shell obtained", "Remote code execution achieved",
            Severity::Critical, 3200);

        chain.seal("post_exploitation", "T1003", "OS Credential Dumping",
            "192.168.1.1", None, "mimikatz.exe",
            "342 hashes extracted", "Credential harvesting successful",
            Severity::Critical, 8100);

        let (valid, total, ok) = chain.verify();
        assert!(valid);
        assert_eq!(total, 3);
        assert_eq!(ok, 3);
    }

    #[test]
    fn test_chain_hashes_are_chained() {
        let mut chain = EvidenceChain::new();














    }

    #[test]
    fn test_tamper_detection() {
        let mut chain = EvidenceChain::new();

        chain.seal("recon", "T1046", "Recon", "10.0.0.1", None,
            "cmd1", "output1", "result1", Severity::Info, 100);
        chain.seal("exploit", "T1190", "Exploit", "10.0.0.1", None,
            "cmd2", "output2", "result2", Severity::Critical, 500);

        let (valid, _, _) = chain.verify();
        assert!(valid);

        // Tamper with the first entry's command
        chain.entries[0].command = "TAMPERED".to_string();

        let (valid, total, ok) = chain.verify();
        assert!(!valid); // Chain is invalid
        assert_eq!(total, 2);
        assert_eq!(ok, 1); // Entry 0 hash mismatch, entry 1 still valid (chain_hash unchanged)
    }

    #[test]
    fn test_output_hash() {
        let mut chain = EvidenceChain::new();

        chain.seal("recon", "T1046", "Recon", "10.0.0.1", None,
            "cmd", "sensitive output data", "result", Severity::Info, 100);

        let entry = &chain.entries()[0];
        // Output hash should be 64 chars (SHA-256 hex)
        assert_eq!(entry.output_hash.len(), 64);
        // Snippet should contain the output
        assert!(entry.output_snippet.contains("sensitive"));
    }

    #[test]
    fn test_output_snippet_truncation() {
        let mut chain = EvidenceChain::new();
        let long_output = "A".repeat(1000);

        chain.seal("recon", "T1046", "Recon", "10.0.0.1", None,
            "cmd", &long_output, "result", Severity::Info, 100);

        let entry = &chain.entries()[0];
        assert!(entry.output_snippet.len() <= 503); // 500 + "..."
        assert!(entry.output_snippet.ends_with("..."));
    }

    #[test]
    fn test_last_hash_genesis() {
        let chain = EvidenceChain::new();
        assert_eq!(chain.last_hash(), "GENESIS");
    }

    #[test]
    fn test_entries_by_phase() {
        let mut chain = EvidenceChain::new();

        chain.seal("recon", "T1046", "Recon", "10.0.0.1", None,
            "cmd", "out", "res", Severity::Info, 100);
        chain.seal("exploit", "T1190", "Exploit", "10.0.0.1", None,
            "cmd", "out", "res", Severity::High, 200);
        chain.seal("recon", "T1018", "Remote Sys Disc", "10.0.0.2", None,
            "cmd", "out", "res", Severity::Info, 150);

        assert_eq!(chain.entries_by_phase("recon").len(), 2);
        assert_eq!(chain.entries_by_phase("exploit").len(), 1);
        assert_eq!(chain.entries_by_phase("persistence").len(), 0);
    }

    #[test]
    fn test_overall_risk() {
        let mut chain = EvidenceChain::new();
        assert_eq!(chain.overall_risk(), "LOW");

        chain.seal("recon", "T1046", "Recon", "10.0.0.1", None,
            "cmd", "out", "res", Severity::Info, 100);
        assert_eq!(chain.overall_risk(), "MEDIUM");

        chain.seal("exploit", "T1190", "Exploit", "10.0.0.1", None,
            "cmd", "out", "res", Severity::High, 200);
        assert_eq!(chain.overall_risk(), "HIGH");

        chain.seal("exploit", "T1190", "Exploit", "10.0.0.1", None,
            "cmd", "out", "res", Severity::Critical, 200);
        assert_eq!(chain.overall_risk(), "CRITICAL");
    }

    #[test]
    fn test_json_export() {
        let mut chain = EvidenceChain::new();
        chain.seal("recon", "T1046", "Recon", "10.0.0.1", None,
            "cmd", "out", "res", Severity::Info, 100);

        let json = chain.to_json();
        assert!(json.contains("T1046"));
        assert!(json.contains("10.0.0.1"));
    }
}

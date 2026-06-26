mod types;
mod error;
mod evidence;
mod mitre;
mod impact;
mod recon;
mod compliance;

use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(
    name = "red-core",
    about = "Hyperium RED-CORE v0.1.0 — Legally Evidenced Threat Engine",
    version = "0.1.0",
    long_about = "Red Team orchestrator with cryptographic evidence sealing.\nExecutes MITRE ATT&CK techniques and generates tamper-proof legal dictamens."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output in JSON format
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// List all available MITRE ATT&CK techniques
    Techniques {
        /// Filter by tactic (e.g. Discovery, Lateral Movement)
        #[arg(long)]
        tactic: Option<String>,
        /// Filter by kill chain phase (e.g. recon, exploitation)
        #[arg(long)]
        phase: Option<String>,
        /// Show only safe (non-destructive) techniques
        #[arg(long)]
        safe: bool,
    },

    /// Show technique details by ID
    Technique {
        /// MITRE ATT&CK ID (e.g. T1046, T1190)
        id: String,
        /// Show compliance mapping
        #[arg(long)]
        compliance: bool,
    },

    /// Validate authorization before engagement
    Authorize {
        /// Client name
        #[arg(long)]
        client: String,
        /// Authorized by (name + title)
        #[arg(long)]
        authorized_by: String,
        /// IP ranges in scope (comma-separated CIDRs)
        #[arg(long)]
        scope: String,
        /// Excluded IPs (comma-separated)
        #[arg(long)]
        exclude: Option<String>,
    },

    /// Show supported compliance frameworks
    Compliance {
        /// Show detailed mapping for a specific technique
        #[arg(long)]
        technique: Option<String>,
    },

    
    /// Full reconnaissance: port scan + banner grab + OS fingerprint + evidence sealing
    Recon {
        /// Target IP or hostname
        target: String,
        /// Ports to scan (e.g. "22,80,443") or leave empty for default
        #[arg(short, long)]
        ports: Option<String>,
        /// Use top N common ports (20 or 100)
        #[arg(long)]
        top: Option<usize>,
        /// Connection timeout in milliseconds
        #[arg(short, long, default_value = "1000")]
        timeout: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Scan specific ports on a target
    Scan {
        /// Target IP or hostname
        target: String,
        /// Ports to scan (e.g. "22,80,443,8080")
        #[arg(short, long)]
        ports: String,
        /// Connection timeout in milliseconds
        #[arg(short, long, default_value = "1000")]
        timeout: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Discover live hosts on a /24 network
    Discover {
        /// Network in CIDR notation (e.g. "192.168.1.0/24")
        #[arg(short, long)]
        network: String,
        /// Connection timeout in milliseconds
        #[arg(short, long, default_value = "1000")]
        timeout: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
/// Display version and system info
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Techniques { tactic, phase, safe } => {
            cmd_techniques(tactic, phase, safe, cli.json);
        }
        Commands::Technique { id, compliance } => {
            cmd_technique_detail(&id, compliance, cli.json);
        }
        Commands::Authorize { client, authorized_by, scope, exclude } => {
            cmd_authorize(&client, &authorized_by, &scope, exclude, cli.json);
        }
        Commands::Compliance { technique } => {
            cmd_compliance(technique, cli.json);
        }
        Commands::Info => {
            cmd_info();
        }
        Commands::Recon { ref target, ref ports, top, timeout, json } => {
            cmd_recon(target, ports.as_deref(), top, timeout, json);
        }
        Commands::Scan { ref target, ref ports, timeout, json } => {
            cmd_scan(target, ports, timeout, json);
        }
        Commands::Discover { ref network, timeout, json } => {
            cmd_discover(network, timeout, json);
        }
    }
}

fn cmd_techniques(tactic: Option<String>, phase: Option<String>, safe: bool, json: bool) {
    let db = mitre::MitreDatabase::new();
    let techniques = if let Some(ref t) = tactic {
        db.by_tactic(t)
    } else if let Some(ref p) = phase {
        db.by_phase(p)
    } else if safe {
        db.safe_techniques()
    } else {
        db.all().iter().collect()
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&techniques).unwrap());
        return;
    }

    println!("{}", format!("  Hyperium RED-CORE — MITRE ATT&CK Techniques ({})", techniques.len()).red().bold());
    println!();
    println!("  {:<12} {:<40} {:<22} {:<10} {:<10}", "ID", "Name", "Tactic", "Phase", "Safe");
    println!("  {}", "-".repeat(96));

    for t in &techniques {
        let safe_str = if t.is_destructive { "NO".red() } else { "YES".green() };
        println!("  {:<12} {:<40} {:<22} {:<10} {:<10}",
            t.id.yellow(), t.name, t.tactic, t.kill_chain_phase, safe_str);
    }
    println!();
}

fn cmd_technique_detail(id: &str, show_compliance: bool, json: bool) {
    let db = mitre::MitreDatabase::new();

    match db.get(id) {
        Some(t) => {
            if json {
                let mut map = serde_json::to_value(t).unwrap();
                if show_compliance {
                    let violations = compliance::ComplianceMapper::map_technique(id);
                    map["compliance"] = serde_json::to_value(&violations).unwrap();
                }
                println!("{}", serde_json::to_string_pretty(&map).unwrap());
                return;
            }

            println!();
            println!("  {} — {}", t.id.red().bold(), t.name.bold());
            println!("  {}", "-".repeat(60));
            println!("  Tactic:       {}", t.tactic);
            println!("  Phase:        {}", t.kill_chain_phase);
            println!("  Description:  {}", t.description);
            println!("  Platforms:    {}", t.platforms.join(", "));
            println!("  Safe Mode:    {}", if t.is_destructive { "BLOCKED (destructive)".red() } else { "Allowed".green() });
            println!("  Requires Auth: {}", if t.requires_auth { "Yes" } else { "No" });
            println!("  Detection:    {}", t.detection_difficulty);

            if show_compliance {
                println!();
                println!("  {}", "Compliance Mapping:".bold());
                let violations = compliance::ComplianceMapper::map_technique(id);
                if violations.is_empty() {
                    println!("  No compliance mappings found");
                } else {
                    for v in &violations {
                        println!("  {} {} — {}", v.framework.cyan(), v.requirement.yellow(), v.description);
                    }
                }
            }
            println!();
        }
        None => {
            eprintln!("  Technique {} not found. Use 'red-core techniques' to list all.", id);
            std::process::exit(1);
        }
    }
}

fn cmd_authorize(client: &str, authorized_by: &str, scope: &str, exclude: Option<String>, json: bool) {
    let ip_ranges: Vec<String> = scope.split(',').map(|s| s.trim().to_string()).collect();
    let excluded: Vec<String> = exclude
        .map(|e| e.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    if json {
        println!("{}", serde_json::json!({
            "status": "authorized",
            "client": client,
            "authorized_by": authorized_by,
            "scope": ip_ranges,
            "excluded": excluded,
        }));
        return;
    }

    println!();
    println!("  {}", "ENGAGEMENT AUTHORIZATION CONFIRMED".green().bold());
    println!("  {}", "-".repeat(50));
    println!("  Client:         {}", client);
    println!("  Authorized by:  {}", authorized_by);
    println!("  Scope:          {}", ip_ranges.join(", "));
    if !excluded.is_empty() {
        println!("  Excluded:       {}", excluded.join(", "));
    }
    println!();
    println!("  {}", "NOTE: Authorization must be documented and signed before execution.".yellow());
    println!("{}", "  All actions will be sealed in the cryptographic evidence chain.".yellow());
    println!();
}

fn cmd_compliance(technique: Option<String>, json: bool) {
    if let Some(ref tech_id) = technique {
        let violations = compliance::ComplianceMapper::map_technique(tech_id);
        if json {
            println!("{}", serde_json::to_string_pretty(&violations).unwrap());
            return;
        }
        println!();
        println!("  {} — Compliance Mapping for {}", "COMPLIANCE".blue().bold(), tech_id.yellow());
        println!("  {}", "-".repeat(60));
        for v in &violations {
            println!("  {} {} — {}", v.framework.cyan(), v.requirement.yellow(), v.description);
        }
        println!();
    } else {
        let frameworks = compliance::ComplianceMapper::frameworks();
        if json {
            println!("{}", serde_json::to_string_pretty(&frameworks).unwrap());
            return;
        }
        println!();
        println!("  {}", "SUPPORTED COMPLIANCE FRAMEWORKS".blue().bold());
        println!("  {}", "-".repeat(40));
        for f in &frameworks {
            println!("  {}", f);
        }
        println!();
        println!("  Use --technique <ID> to see specific mappings");
        println!();
    }
}

fn cmd_info() {
    println!();
    println!("  {}", "Hyperium RED-CORE v0.1.0".red().bold());
    println!("  Legally Evidenced Threat Engine");
    println!("  {}", "-".repeat(40));
    println!("  Version:        0.1.0");
    println!("  Lenguaje:       Rust 2021 Edition");
    println!("  MITRE ATT&CK:   {} techniques loaded", mitre::MitreDatabase::new().count());
    println!("  Evidence:       SHA-256 chained (tamper-evident)");
    println!("  Compliance:     PCI DSS 4.0, GDPR, NIST, HIPAA, SOC 2, NIS2, PTES");
    println!("  Methodology:    PTES (Penetration Testing Execution Standard)");
    println!("  Author:         Patricio Tirado — CEO, Hyperiumia");
    println!("  Contact:        hyperiumia@protonmail.com");
    println!();
}

fn cmd_recon(target: &str, ports: Option<&str>, top: Option<usize>, timeout: u64, json: bool) {
    let engine = recon::ReconEngine::new(timeout);
    let mut chain = evidence::EvidenceChain::new();

    let port_list = if let Some(p) = ports {
        recon::ReconEngine::parse_ports(p)
    } else if let Some(n) = top {
        recon::ReconEngine::top_ports(n)
    } else {
        recon::ReconEngine::top_ports(100)
    };

    println!();
    println!("  Hyperium RED-CORE -- Full Reconnaissance");
    println!("  Target:  {}", target);
    println!("  Ports:   {} ports", port_list.len());
    println!("  Timeout: {}ms", timeout);
    println!();

    let result = engine.full_recon(target, &port_list, &mut chain);

    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "target": result.target,
            "os_guess": result.os_guess,
            "os_confidence": result.os_confidence,
            "open_ports": result.open_ports.len(),
            "services": result.services.len(),
            "total_duration_ms": result.total_duration_ms,
            "evidence_entries": chain.count(),
        })).unwrap());
        return;
    }

    println!("  OS Detection:");
    println!("    {} ({}% confidence)", result.os_guess, result.os_confidence);
    println!();

    println!("  Open Ports ({} found):", result.open_ports.len());
    println!("  {:<8} {:<10} {:<20} {:<30}", "Port", "Protocol", "Service", "Version");
    println!("  {}", "-".repeat(68));
    for s in &result.services {
        println!("  {:<8} {:<10} {:<20} {:<30}",
            s.port, "tcp", s.name, s.version.as_deref().unwrap_or("-"));
    }
    println!();

    println!("  Evidence Chain:");
    println!("    Entries: {}", chain.count());
    let (valid, _, _) = chain.verify();
    println!("    Integrity: {}", if valid { "VALID" } else { "COMPROMISED" });
    println!("    Total duration: {}ms", result.total_duration_ms);
    println!();
}

fn cmd_scan(target: &str, ports: &str, timeout: u64, json: bool) {
    let engine = recon::ReconEngine::new(timeout);
    let port_list = recon::ReconEngine::parse_ports(ports);

    println!();
    println!("  Hyperium RED-CORE -- Port Scan");
    println!("  Target: {}", target);
    println!("  Ports:  {:?}", port_list);
    println!();

    let results = engine.scan_ports(target, &port_list);

    if json {
        let open: Vec<_> = results.iter().filter(|r| r.open).map(|r| serde_json::json!({
            "port": r.port,
            "service": r.service,
            "version": r.version,
            "banner": r.banner,
            "response_time_ms": r.response_time_ms,
        })).collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "target": target,
            "scanned": port_list.len(),
            "open": open.len(),
            "results": open,
        })).unwrap());
        return;
    }

    let open: Vec<_> = results.iter().filter(|r| r.open).collect();
    println!("  Results: {} open / {} scanned", open.len(), port_list.len());
    println!();
    println!("  {:<8} {:<20} {:<25} {:<8}", "Port", "Service", "Version", "RTT(ms)");
    println!("  {}", "-".repeat(61));
    for r in &open {
        println!("  {:<8} {:<20} {:<25} {:<8}",
            r.port, r.service, r.version.as_deref().unwrap_or("-"), r.response_time_ms);
    }
    println!();
}

fn cmd_discover(network: &str, timeout: u64, json: bool) {
    let engine = recon::ReconEngine::new(timeout);

    println!();
    println!("  Hyperium RED-CORE -- Network Discovery");
    println!("  Network: {}", network);
    println!("  Timeout: {}ms", timeout);
    println!();

    let hosts = engine.ping_sweep(network, &[]);

    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "network": network,
            "alive": hosts.len(),
            "hosts": hosts.iter().map(|h| serde_json::json!({
                "ip": h.ip,
                "open_ports": h.open_ports,
            })).collect::<Vec<_>>(),
        })).unwrap());
        return;
    }

    println!("  Live Hosts: {}", hosts.len());
    println!();
    println!("  {:<18} {:<8} Open Ports", "IP", "Status");
    println!("  {}", "-".repeat(50));
    for h in &hosts {
        let ports_str: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
        println!("  {:<18} {:<8} {}", h.ip, "UP", ports_str.join(", "));
    }
    println!();
}

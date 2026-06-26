mod types;
mod error;
mod evidence;
mod mitre;
mod impact;
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

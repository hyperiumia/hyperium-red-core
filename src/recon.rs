use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::io::{Read, Write};

use crate::types::{PortInfo, ServiceInfo, Severity};
use crate::evidence::EvidenceChain;

const TOP_20_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
];

const TOP_100_PORTS: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543,
    544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2100, 2103, 2121, 2199,
    2717, 2869, 2967, 3000, 3001, 3128, 3268, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5120, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 27017,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub port: u16,
    pub open: bool,
    pub banner: Option<String>,
    pub service: String,
    pub version: Option<String>,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ReconOutput {
    pub target: String,
    pub os_guess: String,
    pub os_confidence: u8,
    pub open_ports: Vec<PortInfo>,
    pub services: Vec<ServiceInfo>,
    pub total_duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct HostResult {
    pub ip: String,
    pub alive: bool,
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct OsGuess {
    pub os: String,
    pub confidence: u8,
}

pub struct ReconEngine {
    timeout: Duration,
    banner_timeout: Duration,
}

impl ReconEngine {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            banner_timeout: Duration::from_millis(2000),
        }
    }

    fn resolve(&self, target: &str, port: u16) -> Option<SocketAddr> {
        format!("{}:{}", target, port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
    }

    /// TCP connect scan on a single port
    pub fn scan_port(&self, target: &str, port: u16) -> ScanResult {
        let socket_addr = match self.resolve(target, port) {
            Some(a) => a,
            None => return ScanResult {
                port, open: false, banner: None,
                service: "unknown".to_string(), version: None, response_time_ms: 0,
            },
        };

        let start = Instant::now();
        match TcpStream::connect_timeout(&socket_addr, self.timeout) {
            Ok(mut stream) => {
                let elapsed = start.elapsed().as_millis() as u64;
                stream.set_read_timeout(Some(self.banner_timeout)).ok();
                let banner = self.grab_banner(&mut stream, port);
                let (service, version) = self.detect_service(&banner, port);

                ScanResult { port, open: true, banner, service, version, response_time_ms: elapsed }
            }
            Err(_) => ScanResult {
                port, open: false, banner: None,
                service: "unknown".to_string(), version: None,
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Scan multiple ports
    pub fn scan_ports(&self, target: &str, ports: &[u16]) -> Vec<ScanResult> {
        ports.iter().map(|&p| self.scan_port(target, p)).collect()
    }

    /// Grab banner from open connection
    fn grab_banner(&self, stream: &mut TcpStream, port: u16) -> Option<String> {
        // Send probe for protocols that expect client hello
        let probe = match port {
            80 | 8080 | 8000 | 8008 | 81 | 8443 | 443 => {
                Some(b"HEAD / HTTP/1.0
Host: target

".to_vec())
            }
            25 => Some(b"EHLO test
".to_vec()),
            _ => None, // SSH, FTP, etc. send banner first
        };

        if let Some(data) = probe {
            let _ = stream.write_all(&data);
        }

        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(n) if n > 0 => {
                let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                if banner.is_empty() { None } else { Some(banner) }
            }
            _ => None,
        }
    }

    /// Detect service and version from banner + port
    pub fn detect_service(&self, banner: &Option<String>, port: u16) -> (String, Option<String>) {
        let default = match port {
            21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns",
            80 | 8080 | 8000 | 8008 | 81 => "http", 110 => "pop3", 135 => "msrpc",
            139 => "netbios-ssn", 143 => "imap", 443 | 8443 => "https",
            445 => "microsoft-ds", 993 => "imaps", 995 => "pop3s", 1433 => "ms-sql",
            1723 => "pptp", 3306 => "mysql", 3389 => "rdp", 5432 => "postgresql",
            5900 => "vnc", 27017 => "mongodb", _ => "unknown",
        };

        if let Some(b) = banner {
            let bl = b.to_lowercase();
            let first_line = b.lines().next().unwrap_or("");

            if bl.starts_with("ssh-") {
                return ("ssh".to_string(), Some(first_line.to_string()));
            }
            if bl.starts_with("220") && (bl.contains("ftp") || bl.contains("filezilla") || bl.contains("proftpd") || bl.contains("vsftpd")) {
                return ("ftp".to_string(), Some(first_line.to_string()));
            }
            if bl.contains("server:") {
                if let Some(line) = b.lines().find(|l| l.to_lowercase().starts_with("server:")) {
                    let ver = line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
                    return ("http".to_string(), Some(ver));
                }
            }
            if bl.starts_with("220") && (bl.contains("smtp") || bl.contains("mail") || bl.contains("postfix") || bl.contains("sendmail") || bl.contains("esmtp")) {
                return ("smtp".to_string(), Some(first_line.to_string()));
            }
            if bl.contains("mysql") || (port == 3306 && !bl.is_empty()) {
                return ("mysql".to_string(), Some(first_line.to_string()));
            }
            if bl.starts_with("rfb ") {
                return ("vnc".to_string(), Some(first_line.to_string()));
            }
        }

        (default.to_string(), None)
    }

    /// Heuristic OS fingerprinting (no raw sockets needed)
    pub fn os_fingerprint(&self, _target: &str, open_ports: &[u16], banners: &[Option<String>]) -> OsGuess {
        let (mut win, mut lin, mut mac) = (0i32, 0i32, 0i32);

        // Port heuristics
        if open_ports.contains(&3389) { win += 3; }
        if open_ports.contains(&445)  { win += 2; }
        if open_ports.contains(&135)  { win += 2; }
        if open_ports.contains(&139)  { win += 1; }
        if open_ports.contains(&22)   { lin += 2; }
        if open_ports.contains(&548)  { mac += 3; }
        if open_ports.contains(&5353) { mac += 2; }

        // Banner heuristics
        for b in banners {
            if let Some(b) = b {
                let bl = b.to_lowercase();
                if bl.contains("windows") || bl.contains("microsoft") || bl.contains("iis") { win += 3; }
                if bl.contains("ubuntu") || bl.contains("debian") || bl.contains("centos") || bl.contains("linux") || bl.contains("openssh") { lin += 3; }
                if bl.contains("darwin") || bl.contains("macos") || bl.contains("apple") { mac += 3; }
                if bl.contains("apache") || bl.contains("nginx") { lin += 1; }
            }
        }

        let total = (win + lin + mac) as f64;
        if total == 0.0 {
            return OsGuess { os: "Unknown".to_string(), confidence: 0 };
        }

        if win > lin && win > mac {
            OsGuess { os: "Windows".to_string(), confidence: (win as f64 / total * 100.0) as u8 }
        } else if lin > win && lin > mac {
            OsGuess { os: "Linux".to_string(), confidence: (lin as f64 / total * 100.0) as u8 }
        } else if mac > 0 {
            OsGuess { os: "macOS".to_string(), confidence: (mac as f64 / total * 100.0) as u8 }
        } else {
            OsGuess { os: "Unknown".to_string(), confidence: 0 }
        }
    }

    /// TCP ping sweep on a /24 network
    pub fn ping_sweep(&self, network: &str, probe_ports: &[u16]) -> Vec<HostResult> {
        let parts: Vec<&str> = network.split('/').collect();
        let base = parts[0];
        let prefix: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);
        if prefix != 24 { return vec![]; }

        let octets: Vec<u8> = base.split('.').filter_map(|o| o.parse().ok()).collect();
        if octets.len() != 4 { return vec![]; }

        let ports = if probe_ports.is_empty() { vec![22, 80, 443, 445, 3389] } else { probe_ports.to_vec() };

        (1..=254)
            .map(|i| {
                let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], i);
                let mut open = vec![];
                for &port in &ports {
                    if let Some(addr) = self.resolve(&ip, port) {
                        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
                            open.push(port);
                        }
                    }
                }
                HostResult { ip: ip.clone(), alive: !open.is_empty(), open_ports: open }
            })
            .filter(|h| h.alive)
            .collect()
    }

    /// Full recon: host check, port scan, banner grab, OS fingerprint, seal evidence
    pub fn full_recon(&self, target: &str, ports: &[u16], chain: &mut EvidenceChain) -> ReconOutput {
        let start = Instant::now();

        // 1. Check if host is alive
        let alive = self.check_alive(target);
        chain.seal("recon", "T1046", "Network Service Discovery",
            target, None, &format!("host_check {}", target),
            if alive { "Host alive" } else { "Host unreachable" },
            if alive { "Host responds to TCP connection" } else { "No response" },
            Severity::Info, start.elapsed().as_millis() as u64,
        );

        if !alive {
            return ReconOutput {
                target: target.to_string(), os_guess: "Unknown".to_string(),
                os_confidence: 0, open_ports: vec![], services: vec![],
                total_duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        // 2. Port scan
        let scan_start = Instant::now();
        let results = self.scan_ports(target, ports);
        let scan_dur = scan_start.elapsed().as_millis() as u64;

        let open_ports: Vec<PortInfo> = results.iter().filter(|r| r.open).map(|r| PortInfo {
            port: r.port, protocol: "tcp".to_string(), state: "open".to_string(), banner: r.banner.clone(),
        }).collect();
        let open_nums: Vec<u16> = open_ports.iter().map(|p| p.port).collect();

        chain.seal("recon", "T1046", "Network Service Discovery",
            target, None, &format!("tcp_connect_scan {} ports", ports.len()),
            &format!("{} open: {:?}", open_ports.len(), open_nums),
            &format!("{} of {} ports open", open_ports.len(), ports.len()),
            Severity::Info, scan_dur,
        );

        // 3. Service detection (done during scan via banner grabbing)
        let services: Vec<ServiceInfo> = results.iter().filter(|r| r.open).map(|r| ServiceInfo {
            port: r.port, name: r.service.clone(), version: r.version.clone(),
            product: None, extra_info: r.banner.as_ref().map(|b| {
                let lines: Vec<&str> = b.lines().collect();
                if lines.len() > 1 { lines[1..].join(" ") } else { String::new() }
            }),
        }).collect();

        // 4. OS fingerprint
        let banners: Vec<Option<String>> = results.iter().map(|r| r.banner.clone()).collect();
        let os = self.os_fingerprint(target, &open_nums, &banners);

        chain.seal("recon", "T1592", "Gather Victim Host Information",
            target, None, "os_fingerprint",
            &format!("OS: {} ({}% confidence)", os.os, os.confidence),
            &format!("Based on {} banners, {} open ports",
                banners.iter().filter(|b| b.is_some()).count(), open_ports.len()),
            Severity::Info, 0,
        );

        ReconOutput {
            target: target.to_string(), os_guess: os.os, os_confidence: os.confidence,
            open_ports, services, total_duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn check_alive(&self, target: &str) -> bool {
        for &port in &[80u16, 443, 22, 445, 3389] {
            if let Some(addr) = self.resolve(target, port) {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(1000)).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    pub fn top_ports(n: usize) -> Vec<u16> {
        match n {
            0..=20 => TOP_20_PORTS.to_vec(),
            _ => TOP_100_PORTS.to_vec(),
        }
    }

    pub fn parse_ports(spec: &str) -> Vec<u16> {
        let mut ports = vec![];
        for part in spec.split(",") {
            let part = part.trim();
            if part.contains("-") {
                let range: Vec<&str> = part.split("-").collect();
                if let (Ok(a), Ok(b)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    ports.extend(a..=b);
                }
            } else if let Ok(p) = part.parse() {
                ports.push(p);
            }
        }
        ports.sort();
        ports.dedup();
        ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ssh_banner() {
        let e = ReconEngine::new(1000);
        let b = Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string());
        let (svc, ver) = e.detect_service(&b, 22);
        assert_eq!(svc, "ssh");
        assert!(ver.unwrap().contains("OpenSSH"));
    }

    #[test]
    fn test_detect_http_apache() {
        let e = ReconEngine::new(1000);
        let b = Some("HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)

".to_string());
        let (svc, ver) = e.detect_service(&b, 80);
        assert_eq!(svc, "http");
        assert!(ver.unwrap().contains("Apache"));
    }

    #[test]
    fn test_detect_nginx() {
        let e = ReconEngine::new(1000);
        let b = Some("HTTP/1.1 200 OK
Server: nginx/1.18.0

".to_string());
        let (svc, ver) = e.detect_service(&b, 8080);
        assert_eq!(svc, "http");
        assert!(ver.unwrap().contains("nginx"));
    }

    #[test]
    fn test_detect_ftp_proftpd() {
        let e = ReconEngine::new(1000);
        let b = Some("220 ProFTPD 1.3.5e Server ready.".to_string());
        let (svc, ver) = e.detect_service(&b, 21);
        assert_eq!(svc, "ftp");
        assert!(ver.is_some());
    }

    #[test]
    fn test_detect_smtp_postfix() {
        let e = ReconEngine::new(1000);
        let b = Some("220 mail.example.com ESMTP Postfix (Ubuntu)".to_string());
        let (svc, ver) = e.detect_service(&b, 25);
        assert_eq!(svc, "smtp");
        assert!(ver.is_some());
    }

    #[test]
    fn test_detect_vnc() {
        let e = ReconEngine::new(1000);
        let b = Some("RFB 003.008".to_string());
        let (svc, ver) = e.detect_service(&b, 5900);
        assert_eq!(svc, "vnc");
        assert!(ver.unwrap().contains("RFB"));
    }

    #[test]
    fn test_detect_mysql_banner() {
        let e = ReconEngine::new(1000);
        let b = Some("5.7.38-0ubuntu0.18.04.1".to_string());
        let (svc, _) = e.detect_service(&b, 3306);
        assert_eq!(svc, "mysql");
    }

    #[test]
    fn test_detect_by_port_no_banner() {
        let e = ReconEngine::new(1000);
        assert_eq!(e.detect_service(&None, 3389).0, "rdp");
        assert_eq!(e.detect_service(&None, 445).0, "microsoft-ds");
        assert_eq!(e.detect_service(&None, 5432).0, "postgresql");
        assert_eq!(e.detect_service(&None, 12345).0, "unknown");
    }

    #[test]
    fn test_os_fingerprint_windows() {
        let e = ReconEngine::new(1000);
        let g = e.os_fingerprint("10.0.0.1", &[3389, 445, 135],
            &[Some("Microsoft Terminal Services".to_string())]);
        assert_eq!(g.os, "Windows");
        assert!(g.confidence > 50);
    }

    #[test]
    fn test_os_fingerprint_linux() {
        let e = ReconEngine::new(1000);
        let g = e.os_fingerprint("10.0.0.1", &[22, 80, 443],
            &[Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu".to_string())]);
        assert_eq!(g.os, "Linux");
        assert!(g.confidence > 50);
    }

    #[test]
    fn test_os_fingerprint_unknown() {
        let e = ReconEngine::new(1000);
        let g = e.os_fingerprint("10.0.0.1", &[], &[]);
        assert_eq!(g.os, "Unknown");
        assert_eq!(g.confidence, 0);
    }

    #[test]
    fn test_top_ports_20() {
        let p = ReconEngine::top_ports(20);
        assert_eq!(p.len(), 20);
        assert!(p.contains(&80));
        assert!(p.contains(&443));
        assert!(p.contains(&22));
    }

    #[test]
    fn test_top_ports_100() {
        let p = ReconEngine::top_ports(500);
        assert_eq!(p.len(), 109);
        assert!(p.contains(&8080));
        assert!(p.contains(&5432));
    }

    #[test]
    fn test_parse_ports() {
        let p = ReconEngine::parse_ports("22,80,443,8080");
        assert_eq!(p, vec![22, 80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_range() {
        let p = ReconEngine::parse_ports("20-25,80");
        assert_eq!(p, vec![20, 21, 22, 23, 24, 25, 80]);
    }

    #[test]
    fn test_parse_ports_dedup() {
        let p = ReconEngine::parse_ports("80,80,443,80");
        assert_eq!(p, vec![80, 443]);
    }
}


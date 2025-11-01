#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use super::helpers::{current_apache_pid, httpd_path, CREATE_NO_WINDOW};

// Exit codes: 0=healthy, 1=warning/degraded, 2=stopped, 3=error
pub fn status_once(root: &Path, verbose: bool, probe_url: Option<&str>) -> Result<i32> {
    let pid_opt = current_apache_pid(root)?;
    let httpd = httpd_path(root)?;
    let config_ok = httpd_config_ok(&httpd);
    // Add missing service state discovery
    let service = discover_service_state().unwrap_or(ServiceInfo {
        name: None,
        state: None,
        start_type: None,
    });

    if pid_opt.is_none() {
        // Process not running
        let mut state = "Apache is not running";
        let mut exit_code = 0;

        // If config invalid, escalate to error
        if !config_ok.ok {
            state = "failed";
            exit_code = 3;
        }

        println!("Apache: {}{}", state.to_uppercase(), if verbose { "" } else { "" });
        if let Some(n) = service.state.as_deref() {
            println!("Service: {}", n);
        }
        println!("Config: httpd -t {}", if config_ok.ok { "OK" } else { "ERROR" });
        if !config_ok.ok && verbose {
            if let Some(msg) = config_ok.detail {
                println!("ConfigError: {}", msg.trim());
            }
        }
        return Ok(exit_code);
    }

    // If we have a PID, gather details
    let pid = pid_opt.unwrap();
    let uptime_secs = get_process_uptime_seconds(pid).unwrap_or(0);
    let ports = ports_for_pid(pid).unwrap_or_default();

    // Health probe (optional)
    let mut health_ok: Option<bool> = None;
    let mut health_detail: Option<String> = None;
    if let Some(url) = probe_url.or(Some("http://localhost/server-status?auto")) {
        if url.starts_with("http://") {
            match http_probe(url, Duration::from_millis(1500)) {
                Ok((code, ms)) => {
                    health_ok = Some(code == 200);
                    health_detail = Some(format!("GET {} {} ({} ms)", url, code, ms));
                }
                Err(e) => {
                    health_ok = Some(false);
                    health_detail = Some(format!("GET {} failed: {}", url, e));
                }
            }
        } else if verbose {
            health_detail = Some(format!("Skipping probe (HTTPS not supported in this minimal build): {}", url));
        }
    }

    // Determine state
    let mut state = "running";
    let mut exit_code = 0;

    if !config_ok.ok {
        state = "failed";
        exit_code = 3;
    } else if ports.is_empty() {
        if uptime_secs < 10 {
            state = "starting";
            exit_code = 1;
        } else {
            state = "degraded";
            exit_code = 1;
        }
    } else if let Some(ok) = health_ok {
        if !ok {
            if uptime_secs < 10 {
                state = "starting";
            } else {
                state = "degraded";
            }
            exit_code = 1;
        }
    }

    // If the Windows Service appears stopped while PID exists, mark as degraded/orphaned
    if let Some(s) = service.state.as_deref() {
        if s.to_ascii_lowercase().contains("stopped") {
            state = "degraded";
            exit_code = exit_code.max(1);
        }
    }

    // Output
    println!(
        "Apache: {}  (pid {}){}",
        state.to_uppercase(),
        pid,
        if exit_code == 0 { "  \u{2714} healthy" } else { "" }
    );

    let ports_str = if ports.is_empty() {
        "none".to_string()
    } else {
        ports.join(", ")
    };
    println!(
        "Uptime: {}  | Ports: {}",
        fmt_duration_human(uptime_secs),
        ports_str
    );

    if let Some(n) = service.state.as_deref() {
        let start_ty = service.start_type.as_deref().unwrap_or("Unknown");
        let name = service.name.as_deref().unwrap_or("Apache2.4");
        println!("Service: '{}' = {} ({})", name, n, start_ty);
    }

    println!("Config: httpd -t {}", if config_ok.ok { "OK" } else { "ERROR" });
    if !config_ok.ok && verbose {
        if let Some(msg) = config_ok.detail {
            println!("ConfigError: {}", msg.trim());
        }
    }

    if let Some(hd) = health_detail {
        println!("Health: {}", hd);
    }

    Ok(exit_code)
}

// --- helpers for status ---

struct ConfigCheck {
    ok: bool,
    detail: Option<String>,
}

fn httpd_config_ok(httpd: &Path) -> ConfigCheck {
    let out = Command::new(httpd)
        .arg("-t")
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    match out {
        Ok(o) => {
            let ok = o.status.success();
            let mut msg = String::new();
            if !o.stdout.is_empty() {
                msg.push_str(&String::from_utf8_lossy(&o.stdout));
            }
            if !o.stderr.is_empty() {
                if !msg.is_empty() {
                    msg.push('\n');
                }
                msg.push_str(&String::from_utf8_lossy(&o.stderr));
            }
            ConfigCheck {
                ok,
                detail: if msg.trim().is_empty() { None } else { Some(msg) },
            }
        }
        Err(e) => ConfigCheck {
            ok: false,
            detail: Some(format!("failed to run httpd -t: {}", e)),
        },
    }
}

fn get_process_uptime_seconds(pid: u32) -> Option<u64> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user) }.is_ok();
    unsafe {
        let _ = CloseHandle(handle);
    }
    if !ok {
        return None;
    }
    // Convert FILETIME (100ns since 1601-01-01) to UNIX seconds and diff with now.
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600; // seconds between 1601-01-01 and 1970-01-01
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let started_filetime = filetime_to_u64(create);
    let started_unix = started_filetime / 10_000_000;
    if started_unix < EPOCH_DIFF_SECS {
        return Some(0);
    }
    let started_unix = started_unix - EPOCH_DIFF_SECS;
    if now_unix > started_unix {
        Some(now_unix - started_unix)
    } else {
        Some(0)
    }
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

fn ports_for_pid(pid: u32) -> Result<Vec<String>> {
    let out = Command::new("netstat")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-ano"])
        .output()
        .context("failed to run netstat")?;

    if !out.status.success() {
        return Ok(vec![]);
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut ports = Vec::<String>::new();
    for line in text.lines() {
        // Expect lines with: Proto Local Address Foreign Address State PID
        // or for UDP: Proto Local Address Foreign Address PID
        let l = line.trim();
        if l.is_empty() { continue; }
        if !(l.starts_with("TCP") || l.starts_with("UDP")) { continue; }
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let pid_idx = parts.len() - 1;
        if parts[pid_idx] != pid.to_string() { continue; }
        let local = parts[1];
        // normalize IPv6 like [::]:80 -> [::]:80, keep as-is
        if !ports.contains(&local.to_string()) {
            ports.push(local.to_string());
        }
    }
    Ok(ports)
}

struct ServiceInfo {
    name: Option<String>,
    state: Option<String>,
    start_type: Option<String>,
}

fn discover_service_state() -> Option<ServiceInfo> {
    let candidates = [
        "Apache2.4",
        "Apache24",
        "Apache2.2",
        "ApacheHTTPServer",
    ];
    for name in candidates {
        if let Some(info) = query_service_sc(name) {
            return Some(info);
        }
    }
    None
}

fn query_service_sc(name: &str) -> Option<ServiceInfo> {
    // sc query <name>
    let q = Command::new("sc")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["query", name])
        .output()
        .ok()?;
    if !q.status.success() {
        return None;
    }
    let query_text = String::from_utf8_lossy(&q.stdout);
    let state_line = query_text
        .lines()
        .find(|l| l.trim_start().to_ascii_uppercase().starts_with("STATE"))
        .map(|s| s.trim().to_string());

    // sc qc <name>
    let qc = Command::new("sc")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["qc", name])
        .output()
        .ok()?;
    if !qc.status.success() {
        return Some(ServiceInfo {
            name: Some(name.to_string()),
            state: state_line,
            start_type: None,
        });
    }
    let qc_text = String::from_utf8_lossy(&qc.stdout);
    let start_line = qc_text
        .lines()
        .find(|l| l.trim_start().to_ascii_uppercase().starts_with("START_TYPE"))
        .map(|s| s.trim().to_string());

    Some(ServiceInfo {
        name: Some(name.to_string()),
        state: state_line,
        start_type: start_line,
    })
}

fn http_probe(url: &str, timeout: Duration) -> Result<(u16, u128)> {
    // Very small HTTP/1.0 GET (http only)
    if !url.starts_with("http://") {
        bail!("only http:// is supported");
    }
    let rest = &url["http://".len()..];
    let (host_port, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(80)),
        None => (host_port, 80),
    };

    // Resolve addresses and attempt connect with timeout
    let addrs = (host, port).to_socket_addrs().context("DNS resolve failed")?;
    let start = Instant::now();
    let mut last_err = None;
    let mut stream_opt = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => { stream_opt = Some(s); break; }
            Err(e) => { last_err = Some(e); }
        }
    }
    let mut stream = match stream_opt {
        Some(s) => s,
        None => bail!("connect failed: {}", last_err.map(|e| e.to_string()).unwrap_or_else(|| "unknown error".to_string())),
    };
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let elapsed = start.elapsed().as_millis();
    let text = String::from_utf8_lossy(&buf);
    let status_code = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0u16);
    Ok((status_code, elapsed))
}

pub fn parse_duration(s: &str) -> Option<Duration> {
    let t = s.trim().to_ascii_lowercase();
    if let Some(v) = t.strip_suffix("ms") {
        return v.parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(v) = t.strip_suffix('s') {
        return v.parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(v) = t.strip_suffix('m') {
        return v.parse::<u64>().ok().map(|m| Duration::from_secs(m * 60));
    }
    // default seconds if number
    if let Ok(secs) = t.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    None
}

pub fn fmt_duration_human(secs: u64) -> String {
    let (h, rem) = (secs / 3600, secs % 3600);
    let (m, s) = (rem / 60, rem % 60);
    if h > 0 {
        format!("{}h {}m {}s", h, m, s)
    } else if m > 0 {
        format!("{}m {}s", m, s)
    } else {
        format!("{}s", s)
    }
}

pub fn fmt_duration_short(d: Duration) -> String {
    let ms = d.as_millis();
    if ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{}ms", ms)
    }
}

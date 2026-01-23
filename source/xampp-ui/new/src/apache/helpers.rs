use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};

// --- Constants ---
pub const STARTUP_POLL_ATTEMPTS: usize = 20;
pub const SHUTDOWN_POLL_ATTEMPTS: usize = 20;
pub const POLL_DELAY_MS: u64 = 250;

#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(not(windows))]
pub const CREATE_NO_WINDOW: u32 = 0; // Dummy for Linux

// --- Shared Helper ---
pub fn exec_and_first_line<I, S>(exe: PathBuf, args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    if !exe.exists() {
        return None;
    }
    let output = Command::new(&exe).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().next().map(|line| line.trim().to_string())
}

// --- Platform Specifics ---

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::process::CommandExt;
    use anyhow::anyhow;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
    use windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    pub fn httpd_path(root: &Path) -> Result<PathBuf> {
        let path = root.join("apache").join("bin").join("httpd.exe");
        if path.exists() { Ok(path) } else { bail!("{} not found", path.display()) }
    }

    pub fn pid_file(root: &Path) -> PathBuf {
        root.join("apache").join("logs").join("httpd.pid")
    }

    pub fn kill_process_tree(pid: u32) -> Result<()> {
        let pid_arg = pid.to_string();
        let status = Command::new("taskkill")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/PID", pid_arg.as_str(), "/F", "/T"])
            .status()
            .context("failed to invoke taskkill")?;

        if status.success() { Ok(()) } else { bail!("taskkill returned exit code {:?}", status.code()) }
    }

    pub fn process_matches_httpd(pid: u32, root: &Path) -> Result<bool> {
        let expected = fs::canonicalize(httpd_path(root)?)?;
        let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };
        let image = query_process_image(handle);
        unsafe { let _ = CloseHandle(handle); }
        let actual = match image {
            Ok(path) => path,
            Err(_) => return Ok(false),
        };
        match fs::canonicalize(actual) {
            Ok(actual_path) => Ok(actual_path == expected),
            Err(_) => Ok(false),
        }
    }

    fn query_process_image(handle: HANDLE) -> Result<PathBuf> {
        let mut capacity: usize = 260; 
        loop {
            let mut buffer = vec![0u16; capacity];
            let written = unsafe { K32GetModuleFileNameExW(Some(handle), Some(HMODULE::default()), &mut buffer) } as usize;
            if written == 0 { return Err(anyhow!("unable to query process image")); }
            if written + 1 < buffer.len() {
                let os_string = OsString::from_wide(&buffer[..written]);
                return Ok(PathBuf::from(os_string));
            }
            capacity *= 2;
            if capacity > 32_768 { return Err(anyhow!("process image path exceeded buffer")); }
        }
    }

    pub fn find_apache_pid_by_process(root: &Path) -> Result<Option<u32>> {
        let out = Command::new("tasklist")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/FI", "IMAGENAME eq httpd.exe", "/FO", "CSV", "/NH"])
            .output()?;
        if !out.status.success() { return Ok(None); }
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let l = line.trim().trim_matches('"');
            if l.is_empty() || l.starts_with("INFO:") { continue; }
            let mut cols = l.split("\",\"");
            let _image = cols.next();
            let pid_str = cols.next();
            if let Some(pid_s) = pid_str {
                if let Ok(pid) = pid_s.parse::<u32>() {
                    if process_matches_httpd(pid, root)? { return Ok(Some(pid)); }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::fs;

    pub fn httpd_path(root: &Path) -> Result<PathBuf> {
        // Linux XAMPP standard path
        let path = root.join("bin").join("httpd");
        if path.exists() { Ok(path) } else { bail!("{} not found", path.display()) }
    }

    pub fn pid_file(root: &Path) -> PathBuf {
        root.join("logs").join("httpd.pid")
    }

    pub fn kill_process_tree(pid: u32) -> Result<()> {
        // On Linux, Apache handles children when parent receives SIGTERM.
        // We use the `kill` command to avoid bringing in signal crates just for this.
        let status = Command::new("kill")
            .arg(pid.to_string())
            .status()
            .context("failed to invoke kill")?;
        
        if status.success() { Ok(()) } else { bail!("kill returned exit code {:?}", status.code()) }
    }

    pub fn process_matches_httpd(pid: u32, root: &Path) -> Result<bool> {
        let expected = match fs::canonicalize(httpd_path(root)?) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        
        let link_path = format!("/proc/{}/exe", pid);
        let actual = match fs::read_link(&link_path) {
            Ok(p) => p,
            Err(_) => return Ok(false), // Process likely doesn't exist or permission denied
        };

        // Compare paths
        match fs::canonicalize(actual) {
            Ok(actual_path) => Ok(actual_path == expected),
            Err(_) => Ok(false),
        }
    }

    pub fn find_apache_pid_by_process(root: &Path) -> Result<Option<u32>> {
        // Iterate over /proc
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() { continue; }
            
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            
            if let Ok(pid) = fname_str.parse::<u32>() {
                if process_matches_httpd(pid, root)? {
                    return Ok(Some(pid));
                }
            }
        }
        Ok(None)
    }
}

// Re-export implementations
pub use imp::*;

// --- Shared Logic ---

pub fn cleanup_pid_file(root: &Path) {
    let pid_path = pid_file(root);
    if pid_path.exists() {
        let _ = fs::remove_file(pid_path);
    }
}

pub fn wait_for_apache_pid(root: &Path, attempts: usize) -> Result<Option<u32>> {
    for _ in 0..attempts {
        if let Some(pid) = read_pid(root)? {
            if process_matches_httpd(pid, root)? {
                return Ok(Some(pid));
            }
        }
        thread::sleep(Duration::from_millis(POLL_DELAY_MS));
    }
    Ok(None)
}

pub fn wait_for_shutdown(root: &Path, attempts: usize) -> Result<()> {
    for _ in 0..attempts {
        if current_apache_pid(root)?.is_none() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(POLL_DELAY_MS));
    }
    bail!("Apache process did not exit in time");
}

pub fn current_apache_pid(root: &Path) -> Result<Option<u32>> {
    let Some(pid) = read_pid(root)? else {
        return find_apache_pid_by_process(root);
    };

    if process_matches_httpd(pid, root)? {
        Ok(Some(pid))
    } else {
        find_apache_pid_by_process(root)
    }
}

fn read_pid(root: &Path) -> Result<Option<u32>> {
    let path = pid_file(root);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let pid = trimmed
        .parse::<u32>()
        .with_context(|| format!("invalid PID in {}", path.display()))?;
    Ok(Some(pid))
}
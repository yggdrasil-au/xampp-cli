# WLAP-Server-CLI

# xampp-cli-control

command line version of xampp control panel


Here's a polished **README.md** you can drop into the project root:

---

# 🧰 LampCTL — XAMPP Apache Control CLI

> A **Rust-based CLI** that re-implements the **Windows XAMPP Control Panel**'s **Apache controls** with **1:1 feature parity**, minus the GUI.

LampCTL is a lightweight command-line replacement for `xampp-control.exe` focused solely on **Apache**.
It uses the **actual XAMPP build** on disk — no external dependencies, no re-implementations — and can live **right next to the original control panel** inside your XAMPP directory.

---

## ✨ Features

* 🧭 **Apache-only control**, matching the Pascal GUI's functionality:

  * Start / Stop / Restart Apache
  * Register virtual hosts with automatic configuration
  * Open `httpd.conf`, `error.log`, and `http://localhost/` (Admin)
  * Status monitoring with detailed information
* 🪄 Works **out of the box** — just drop the binary into your XAMPP root (e.g., `C:\xampp`).
* 🧱 Uses the **real `httpd.exe`** shipped with XAMPP, exactly like the GUI.
* 🔧 **Smart project management**:
  * Auto-generates unique project IDs (timestamp-based)
  * Automatic port selection when not specified
  * Tracks creation and update timestamps
  * Validates port availability (system + config)
* 🪟 Windows-only, zero external runtime dependencies.

---

## 📦 Installation

1. Download a **standard Windows XAMPP distribution** (e.g. from [apachefriends.org](https://www.apachefriends.org/)).
2. Place the compiled `lampctl.exe` binary **inside the XAMPP root folder**, next to `xampp-control.exe`:

```
C:\xampp\
├── apache\
├── php\
├── xampp-control.exe
└── lampctl.exe   ← here
```

3. Add `C:\xampp` to your system `PATH`.

---

## 🧭 Usage

LampCTL mirrors the original GUI controls, but through a clean CLI:

```pwsh
lampctl apache <action>
```

### Available Actions

| Action              | Description                                                 |
| ------------------- | ----------------------------------------------------------- |
| `start`             | Start Apache (foreground) - auto-registers project if none exists |
| `stop`              | Stop Apache                                                 |
| `restart`           | Restart Apache                                              |
| `status`            | Show Apache status (PID, uptime, ports, health)            |
| `register`          | Register a virtual host configuration                       |
| `logs`              | Open `apache\logs\error.log` in default editor/viewer       |
| `admin`             | Open [http://localhost/](http://localhost/) in your browser |
| `config`            | Open `apache\conf\httpd.conf` in default editor             |

### Examples

```pwsh
# Start Apache (auto-registers project with smart port selection if .lampctl-project.conf doesn't exist)
lampctl apache start

# Start Apache with specific document root and port
lampctl apache start --document-root .\example-www\ --port 8080

# Register a new virtual host (or update existing one)
lampctl apache register --document-root .\example-www\ --port 80

# Update an existing project's port
lampctl apache register --document-root .\example-www\ --port 3000

# Check Apache status
lampctl apache status

# Watch status with auto-refresh (checks every 2 seconds)
lampctl apache status --watch 2s

# Stop Apache
lampctl apache stop

# Restart Apache
lampctl apache restart

# Open error log
lampctl apache logs

# Open Apache config
lampctl apache config
```

### Virtual Host Management

LampCTL provides intelligent virtual host management:

**Project Configuration:**
- Each project directory gets a `.lampctl-project.conf` file tracking:
  - Unique project ID (timestamp-based)
  - Port number
  - Document root
  - VHost config file location
  - Creation and last update timestamps

**Smart Port Selection:**
- When registering without specifying a port, LampCTL tries common ports in order:
  - 80, 8080, 3000, 8000, 8888, 5000, 3333, 4444, 5555, 7777, 9000, 9999
  - Falls back to high ports (10000-10100) if all are taken
- Validates ports against both system (netstat) and existing vhost configs
- Prevents port conflicts automatically

**Update Existing Projects:**
- Running `register` again in the same directory updates the existing vhost
- Preserves the original creation date
- Updates port and/or document root as specified
- Tracks last update timestamp

---

## 🛠️ Other Commands

```pwsh
lampctl version   # Show LampCTL, Apache, and PHP versions
lampctl root      # Print detected XAMPP root (location of the EXE)
```

### Status Command Options

The `status` command provides detailed Apache information:

```pwsh
# Basic status check
lampctl apache status

# Verbose output with additional details
lampctl apache status --verbose

# Watch mode with auto-refresh (checks every interval)
lampctl apache status --watch 5s     # Refresh every 5 seconds
lampctl apache status --watch 500ms  # Refresh every 500 milliseconds
lampctl apache status --watch 2m     # Refresh every 2 minutes

# Custom health probe URL
lampctl apache status --probe http://localhost:8080/health

# Combine options
lampctl apache status --verbose --watch 3s --probe http://localhost/server-status
```

**Status Output:**
- Process state (RUNNING, STOPPED, DEGRADED, ERROR)
- PID and uptime
- Listening ports
- Windows service state (if applicable)
- Configuration validity (httpd -t check)
- Health probe results (if enabled)

---

## ⚡ Design Notes

* The tool **does not modify configs** (except for virtual host registration), only invokes existing `httpd.exe` commands exactly like the Pascal GUI.
* All paths are **relative to the binary's location**, so double-clicking or PATH invocation works reliably.
* Only **Apache** is supported. MySQL/FileZilla/Mercury/Tomcat are intentionally **ignored**.
* Service features not implemented in this tool, only foreground run instances.
* **Virtual host configs** are automatically managed in `apache\conf\extra\httpd-vhosts.conf` with clear markers.
* Each project gets a `.lampctl-project.conf` file to track configuration and enable updates.

---

## 🧪 Building from Source

```pwsh
# Install Rust (https://rustup.rs/)
cargo build --release

# The binary will be in:
target/release/lampctl.exe
```

Copy `lampctl.exe` into your XAMPP root folder.

---

## 📝 License

MIT License © 2025
This project is not affiliated with Apache Friends or XAMPP.

---

Would you like me to add badges (build status, Rust version, etc.) to the top of the README as well?

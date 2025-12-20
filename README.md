# the xampp-cli - WlampCTL

**A modern, CLI-driven reimagining of the XAMPP development environment.**

The ultimate goal of this project is to create a development tool similar to Vite in usecase, but built upon a re-implementation of the XAMPP stack. It aims to provide a lightweight, cross-platform, and scriptable environment for PHP/Apache development.

## Project Components

### 1. CLI Control Panel (`source/xampp-ui/new`)
*Status: Active Development (Rust)*

A command-line replacement for the classic `xampp-control.exe`.

*   **Current Functionality**: Operates as a drop-in replacement for the XAMPP GUI. It currently supports controlling **Apache** (Start, Stop, Restart, Status, Config).
*   **Design**: Re-implements the logic of the original Perl/Delphi GUI but as a modern CLI tool.
*   **Requirements**: Must be placed inside a valid XAMPP installation root (next to `xampp-control.exe`).

### 2. XAMPP Builder (`source/xampp-build`)
*Status: Planned / Concept*

A re-implementation of the XAMPP installer and build tools.

*   **Goal**: To replace the complex legacy build scripts with a smaller, simpler, and modern toolchain.
*   **Scope**: Stripped down to essentials (Apache, maybe MySQL) to reduce bloat.

## Roadmap

*   **Cross-Platform Support**: Moving beyond Windows-only dependencies.
*   **GUI**: A modern C# wrapper around the Rust CLI Core to provide a visual interface.
*   **Full Stack Control**: Adding support for MySQL and other components.

---

# WlampCTL — XAMPP Apache Control CLI

> A **Rust-based CLI** that re-implements the **Windows XAMPP Control Panel**'s **Apache controls** with **1:1 feature parity**, minus the GUI.

**WlampCTL** stands for **W**indows **L**inux **A**pache **M**odern **P**HP **C**on**t**ro**l**.

WlampCTL is a lightweight command-line replacement for `xampp-control.exe` focused solely on **Apache**.
It uses the **actual XAMPP build** on disk — no external dependencies, no re-implementations — and can live **right next to the original control panel** inside your XAMPP directory.

## ✨ Features

* 🧭 **Apache-only control**, matching the Pascal GUI's functionality:
  * Start / Stop / Restart
  * Configuration editing (`httpd.conf`)
  * Admin page launch
  * Log viewing
  * Status monitoring with detailed information
* 🪄 Works **out of the box** — just drop the binary into your XAMPP root (e.g., `C:\xampp`).
* 🧱 Uses the **real `httpd.exe`** shipped with XAMPP, exactly like the GUI.
* 🔧 **Smart project management**:
  * Auto-generates unique project IDs
  * Manages VirtualHosts automatically
  * Validates port availability

## 📦 Installation

1.  Download or build `wlampctl.exe`.
2.  Place the binary **inside the XAMPP root folder**, next to `xampp-control.exe`:

```
C:\xampp\
├── apache\
├── php\
├── xampp-control.exe
└── wlampctl.exe   ← here
```

## 🧭 Usage

```pwsh
wlampctl apache <action>
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
# Start Apache (auto-registers project with smart port selection if .wlampctl-project.conf doesn't exist)
wlampctl apache start

# Start Apache with specific document root and port
wlampctl apache start --document-root .\example-www\ --port 8080

# Register a new virtual host (or update existing one)
wlampctl apache register --document-root .\example-www\ --port 80

# Update an existing project's port
wlampctl apache register --document-root .\example-www\ --port 3000

# Check Apache status
wlampctl apache status

# Watch status with auto-refresh (checks every 2 seconds)
wlampctl apache status --watch 2s

# Stop Apache
wlampctl apache stop

# Restart Apache
wlampctl apache restart

# Open error log
wlampctl apache logs

# Open Apache config
wlampctl apache config
```

### Virtual Host Management

WlampCTL provides intelligent virtual host management:

**Project Configuration:**
- Each project directory gets a `.wlampctl-project.conf` file tracking:
  - Unique project ID (timestamp-based)
  - Port number
  - Document root
  - VHost config file location
  - Creation and last update timestamps

**Smart Port Selection:**
- When registering without specifying a port, WlampCTL tries common ports in order:
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
wlampctl version   # Show WlampCTL, Apache, and PHP versions
wlampctl root      # Print detected XAMPP root (location of the EXE)
```

### Status Command Options

The `status` command provides detailed Apache information:

```pwsh
# Basic status check
wlampctl apache status

# Verbose output with additional details
wlampctl apache status --verbose

# Watch mode with auto-refresh (checks every interval)
wlampctl apache status --watch 5s     # Refresh every 5 seconds
wlampctl apache status --watch 500ms  # Refresh every 500 milliseconds
wlampctl apache status --watch 2m     # Refresh every 2 minutes

# Custom health probe URL
wlampctl apache status --probe http://localhost:8080/health

# Combine options
wlampctl apache status --verbose --watch 3s --probe http://localhost/server-status
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
* Each project gets a `.wlampctl-project.conf` file to track configuration and enable updates.

---

## 🧪 Building from Source

```pwsh
# Install Rust (https://rustup.rs/)
cargo build --release

# The binary will be in:
target/release/wlampctl.exe
```

Copy `wlampctl.exe` into your XAMPP root folder.

---

## 📝 License

MIT License © 2025
This project is not affiliated with Apache Friends or XAMPP.

# SSHM: Secure Cross-Platform SSH & SFTP Manager

**SSHM** (`sshm`) is a secure, production-ready, standalone cross-platform CLI tool for managing SSH server connections, establishing port-forwarding tunnels, and transferring files over SFTP.

Built with **Go**, `golang.org/x/crypto/ssh`, `github.com/pkg/sftp`, and `github.com/spf13/cobra`, SSHM runs natively as a single binary on **macOS**, **Linux**, and **Windows**.

---

## Key Features

* 🔐 **Secure Credential Vault**: Dual-tier architecture separating non-sensitive profile metadata (`profiles.json`) from credentials (`vault.enc`), encrypted with **AES-256-GCM** and **Argon2id**. Integrates natively with the OS Keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service).
* 🛡️ **Zero Secret Leakage**: Secrets (passwords, private keys, passphrases) are never accepted as CLI arguments, never printed in logs or errors, excluded from `list` and `--json`, and zeroed in memory after use.
* 🖥️ **Interactive Terminal Shell (`sshm open` / `sshm shell`)**: Native PTY allocation, raw mode, window resizing (`SIGWINCH` on Unix, console resize monitor on Windows), signal handling, and accurate exit status propagation.
* 🚇 **Port Forwarding & Tunneling (`sshm tunnel`)**:
  * **Local Port Forwarding (`-L`)**: Connect server's remote port 80 to a local port (e.g., `-L 8080:localhost:80`).
  * **Remote Port Forwarding (`-R`)**: Expose local services on the remote server.
  * **Dynamic Port Forwarding (`-D`)**: Built-in SOCKS5 proxy routed through SSH.
  * On-the-fly forwarding while running an interactive shell (`sshm open prod -L 8080:80`).
* 📁 **Interactive SFTP File Browser (`sshm files`)**: Keyboard-driven terminal file manager to browse, upload, download, rename, and delete remote files.
* 🚀 **Streaming SFTP File Transfers (`sshm upload` / `sshm download`)**:
  * Real-time progress bar with percentage, transfer speed (MB/s), and ETA.
  * Recursive directory uploads and downloads.
  * Chunk-based streaming I/O (no buffering large files into memory).
* 🔄 **OpenSSH Config Importer (`sshm import`)**: Seamlessly parses `~/.ssh/config` and imports existing hosts with interactive preview.
* 🔑 **Strict Host Key Verification**: OpenSSH-style `known_hosts` verification with SHA256 fingerprints, unknown key prompts, and Man-In-The-Middle (MITM) detection.
* 📦 **Standalone Single Binary**: Zero external dependencies (no Python, Node.js, or Java runtime needed).

---

## Installation

### Pre-built Binaries

Download the appropriate binary for your OS and architecture:

| Platform | Architecture | Binary |
| :--- | :--- | :--- |
| **macOS** | Apple Silicon (M1/M2/M3) | `sshm-darwin-arm64` |
| **macOS** | Intel | `sshm-darwin-amd64` |
| **Linux** | AMD64 (x86_64) | `sshm-linux-amd64` |
| **Linux** | ARM64 (aarch64) | `sshm-linux-arm64` |
| **Windows** | AMD64 (64-bit) | `sshm-windows-amd64.exe` |
| **Windows** | ARM64 | `sshm-windows-arm64.exe` |

#### macOS / Linux Install:
```bash
chmod +x sshm-darwin-arm64
sudo mv sshm-darwin-arm64 /usr/local/bin/sshm
sshm --version
```

#### Windows Install:
Move `sshm-windows-amd64.exe` into a folder included in your system `PATH` (such as `C:\Program Files\sshm\sshm.exe`).

### Building from Source

Requirements: Go 1.23+ and Make.

```bash
git clone https://github.com/alwin/sshm.git
cd sshm
make build
./bin/sshm --version
```

To cross-compile for all supported platforms:
```bash
make cross-compile
ls -lh dist/
```

---

## Quick Start Guide

### 1. Adding an SSH Server Profile

Launch the interactive wizard:
```bash
sshm add production
```

```text
SSH Profile: production

Host/IP: 203.0.113.10
Port [22]: 22
Username: ubuntu

Authentication:
1. Private Key
2. Password
3. SSH Agent
Select [1]: 1

Private Key Path [~/.ssh/id_ed25519]: ~/.ssh/production.pem
Store key copy encrypted inside vault? [y/N]: n
Does this private key require a passphrase? [y/N]: y
Key Passphrase: ********

Save configuration? [Y/n]: y
✓ SSH configuration "production" saved securely.
```

### 2. Listing Profiles

```bash
sshm list
```

Output:
```text
NAME          HOST              PORT    USER       AUTH           PROXY
production    203.0.113.10      22      ubuntu     KEY            -
staging       staging.example   22      deploy     KEY (VAULT)    -
database      10.0.0.20         2222    admin      PASSWORD       jump:bastion
```

For automation, output structured JSON (guaranteed secret-free):
```bash
sshm list --json
```

### 3. Connecting to a Server (`open` / `shell`)

Open an interactive SSH session:
```bash
sshm open production
```
Or use the explicit alias:
```bash
sshm shell production
```

SSHM handles terminal resizing, Ctrl+C, Ctrl+D, and forwards remote exit codes cleanly upon disconnecting.

---

## Port Forwarding & Tunneling

### Connect Remote Server Port 80 to Local Port 8080

To forward port 80 of your remote server to a local port (e.g. `localhost:8080`):
```bash
sshm tunnel production -L 8080:localhost:80
```
*(Or shorthand: `sshm tunnel production -L 8080:80`)*

Now open your local web browser and navigate to:
```text
http://localhost:8080
```
All traffic is securely tunneled through your SSH connection directly to the server's internal port 80.

### Additional Tunnel Options

* **Remote Forwarding** (expose local port 3000 on remote port 9000):
  ```bash
  sshm tunnel production -R 9000:localhost:3000
  ```
* **Dynamic SOCKS5 Proxy**:
  ```bash
  sshm tunnel production -D 1080
  ```
* **Open Interactive Shell with Port Tunnel Active**:
  ```bash
  sshm open production -L 8080:localhost:80
  ```

---

## SFTP File Transfers

### Uploading Files and Directories
```bash
# Upload a single file
sshm upload production ./app.tar.gz /opt/app/

# Upload an entire directory recursively
sshm upload production ./dist/ /var/www/html/
```

Displays an animated streaming progress bar:
```text
Uploading app.tar.gz
████████████████████░░░░░░░░   68%
342.0 MB / 502.0 MB  •  Speed: 18.4 MB/s  •  ETA: 9s
```

### Downloading Files and Directories
```bash
# Download a remote log file
sshm download production /var/log/app.log ./logs/

# Download a remote directory recursively
sshm download production /opt/app/backup/ ./local_backups/
```

---

## Interactive SFTP File Manager

Launch a terminal-based remote file explorer:
```bash
sshm files production
```

```text
production:/var/www/

> app/
  config/
  public/
  index.html
  app.tar.gz

Commands:
Enter: Open dir | -: Parent dir | U: Upload | D: Download
R: Rename       | X: Delete     | N: New dir| Q: Quit
```

---

## Profile Management

### Editing a Profile

* **Interactive Menu**:
  ```bash
  sshm edit production
  ```
* **Command-line Flags**:
  ```bash
  sshm edit production --host 203.0.113.20 --port 2222 --user deploy
  ```
* **Updating Password / Passphrase**:
  *(Prompts securely without echoing or exposing in shell history)*
  ```bash
  sshm edit production --password
  ```

### Renaming a Profile
```bash
sshm rename production production-eu
```
Preserves all connection options and encrypted vault credentials under the new name.

### Deleting a Profile
```bash
# Prompts for confirmation by typing profile name
sshm delete production-eu

# Non-interactive override for automation
sshm delete production-eu --yes
```

---

## Credential Vault Management

SSHM manages master encryption keys automatically via your OS Keyring. You can inspect or control vault security explicitly:

```bash
# Inspect vault lock state, profile count, and keyring backend
sshm vault status

# Lock the vault (removes key from memory and OS keyring)
sshm vault lock

# Unlock the vault using your master passphrase
sshm vault unlock
```

### Encrypted Backups (Export & Import)

To create an encrypted backup of your profiles and credentials:
```bash
sshm vault export my-backup.sshm
```
*(Prompts for a dedicated export passphrase; file remains encrypted with AES-256-GCM)*

To restore from an encrypted backup:
```bash
sshm vault import my-backup.sshm
```

---

## Importing from OpenSSH `~/.ssh/config`

Import your existing SSH configuration without manually re-entering hosts:
```bash
sshm import ~/.ssh/config
```

SSHM displays a preview:
```text
Found 3 SSH hosts:

1. production         (203.0.113.10:22, user: ubuntu)
2. staging            (staging.example:22, user: deploy)
3. database           (10.0.0.20:2222, user: admin)

Import discovered profiles? [Y/n]: y
✓ Import complete: 3 imported, 0 skipped.
```

---

## Host Key Verification

SSHM strictly verifies remote server host keys against `~/.ssh/known_hosts`:
* **Unknown Key**: Displays the key type and SHA256 fingerprint, prompting for explicit confirmation before saving.
* **Changed Key**: Detects potential Man-In-The-Middle attacks and displays a prominent security alert:
  ```text
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
  Someone could be eavesdropping on you right now (man-in-the-middle attack)!
  ```

---

## Global Flags

* `--debug`: Enable verbose diagnostic logging (credentials and keys are automatically redacted).
* `--config <path>`: Specify a custom configuration directory (default: `~/.sshm`).
* `--plain`: Disable ANSI colors and Unicode symbols for plain-text / scripting environments.

---

## Architecture & Future GUI Compatibility

SSHM is structured into decoupled layers:
```text
sshm/
├── cmd/sshm/             # Executable entry point
├── pkg/models/           # Profile, credential models & domain validation
├── internal/
│   ├── cli/              # Cobra commands, terminal UI, and prompt handlers
│   ├── vault/            # Cryptographic vault & OS Keyring service
│   ├── ssh/              # SSH client, PTY session, & port tunneling engine
│   ├── sftp/             # SFTP operations & decoupled file browser model
│   ├── transfer/         # Streaming transfer engine with progress tracking
│   ├── knownhosts/       # Host-key verification and fingerprint engine
│   └── sshconfig/        # OpenSSH config parser
└── testserver/           # In-process mock SSH/SFTP server for testing
```
The services in `internal/` (Vault, SSH, SFTP, Transfer) do not depend on terminal UI libraries. A graphical desktop application (e.g., Wails, Fyne, or Flutter) can directly import and reuse these core services without modifications.

---

## Testing

Run all unit, integration, and security tests with race detection:
```bash
go test -v -race ./...
```

Run static analysis:
```bash
go vet ./...
```

---

## License

MIT License. See [LICENSE](file:///Users/alwin/code/sshm/LICENSE) for details.

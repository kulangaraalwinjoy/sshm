# Security Policy & Threat Model

Security is the foremost design requirement of **SSHM**. As a credential-management and remote access application, SSHM adheres to strict cryptographic and secret-handling principles.

This document details the security architecture, cryptographic primitives, threat model, protections, and threat boundaries.

---

## 1. Cryptographic Architecture

SSHM employs standard, audited cryptographic algorithms provided by Go's standard library and `golang.org/x/crypto`. Custom cryptography is strictly forbidden.

### 1.1 Credential Encryption
* **Cipher**: AES-256-GCM (Galois/Counter Mode).
* **Authenticated Encryption**: Every ciphertext block includes a 16-byte authentication tag ensuring integrity and tamper detection.
* **Nonce**: 12-byte cryptographically secure pseudorandom nonce generated via `crypto/rand` per encryption event. Nonces are never reused.
* **Envelope Magic Header**: `SSHMVAULT` + Version byte (`0x01`) + 16-byte salt + 12-byte nonce + ciphertext + auth tag.

### 1.2 Key Derivation Function (KDF)
* **Algorithm**: **Argon2id** (the hybrid version of Argon2, resistant to both GPU/ASIC side-channel attacks and tradeoff attacks).
* **Parameters**:
  * Memory: 64 MB (65,536 KiB)
  * Iterations: 3 passes
  * Parallelism: 4 threads
  * Salt: 16 bytes generated from `crypto/rand`
  * Derived Key: 32 bytes (256 bits)

### 1.3 Master Key Protection & OS Keyring Integration
SSHM features a dual-tier protection mechanism:
1. **OS Native Keyring**:
   * **macOS**: Apple Keychain Services.
   * **Windows**: Windows Credential Manager (`wincred`).
   * **Linux**: FreeDesktop Secret Service via D-Bus.
2. **Headless / Air-gapped Fallback**:
   * If an OS keyring daemon is not available (e.g., CI/CD pipelines, Docker containers, remote headless servers), SSHM derives the master key directly from the user's master passphrase in memory on demand.
3. **Explicit Vault Locking**:
   * Running `sshm vault lock` immediately zeroes the in-memory master key and clears the entry from the OS Keyring.

---

## 2. Threat Model & Analysis

### 2.1 Stolen Laptop / Offline Disk Theft
* **Scenario**: An attacker obtains physical possession of a powered-off device or accesses an offline disk image.
* **Protection**:
  * Profile metadata in `profiles.json` contains no secrets (no passwords, private keys, or passphrases).
  * Secrets reside exclusively in `vault.enc`, protected by AES-256-GCM.
  * Without the user's master passphrase or OS Keychain access, brute-forcing the AES-256 key via Argon2id is computationally infeasible.

### 2.2 Unauthorized Local User (Multi-User Environment)
* **Scenario**: Another user on the same operating system attempts to read stored credentials.
* **Protection**:
  * SSHM enforces `0700` directory permissions on `~/.sshm` and `0600` permissions on `profiles.json` and `vault.enc`.
  * On Unix-like systems, non-root users cannot read files with `0600` permissions owned by another user.
  * Credentials stored in the OS keyring are protected by OS-level access control policies.

### 2.3 Vault File Theft
* **Scenario**: An attacker exfiltrates `vault.enc`.
* **Protection**:
  * The file is fully encrypted with AES-256-GCM and salted with 16 bytes of cryptographic entropy.
  * Tampering with ciphertext causes authentication failure immediately upon decryption (`ErrWrongPassphrase` or `ErrInvalidCiphertext`).

### 2.4 Accidental Credential Disclosure (CLI & JSON)
* **Scenario**: A user runs `sshm list` or `sshm list --json` in front of colleagues or streams their terminal.
* **Protection**:
  * Neither table output nor JSON output ever serializes passwords, private keys, or passphrases.
  * `ProfileCredentials` fields are excluded from `SSHProfile`.

### 2.5 Shell History Exposure
* **Scenario**: Secrets are passed as CLI arguments and logged to `~/.bash_history` or `~/.zsh_history`.
* **Protection**:
  * SSHM prohibits passing passwords or passphrases as command-line argument values (e.g. `sshm edit prod --password "secret"` is rejected).
  * Passing `--password` triggers a hidden terminal prompt via `golang.org/x/term.ReadPassword` which does not echo characters and never enters shell history.

### 2.6 Debug Log Exposure
* **Scenario**: A user enables `--debug` to troubleshoot connection issues and shares the output.
* **Protection**:
  * The diagnostic logger automatically runs all log entries through a regex-based redaction engine.
  * Passwords, tokens, passphrases, and PEM private key blocks are replaced with `[REDACTED]` or `[REDACTED PRIVATE KEY]`.

### 2.7 Host-Key Spoofing & MITM Attacks
* **Scenario**: An attacker intercepts traffic between SSHM and the server, presenting a fake host key.
* **Protection**:
  * SSHM enforces strict host-key verification against `~/.ssh/known_hosts`.
  * If a host key has **changed**, SSHM displays a prominent security warning, treats it as a potential Man-In-The-Middle attack, and aborts by default under `StrictHostKeyChecking=yes` or `ask`.
  * For unknown host keys, SSHM displays the SHA256 fingerprint and requires explicit user confirmation before recording the key.

### 2.8 Malicious SSH Server
* **Scenario**: A compromised or hostile SSH server attempts to exploit the client.
* **Protection**:
  * SSH protocol parsing is delegated to `golang.org/x/crypto/ssh`, a memory-safe Go implementation immune to C-style buffer overflows.
  * Agent forwarding (`ForwardAgent`) is disabled by default and only enabled if explicitly configured per profile.

### 2.9 Backup Leakage
* **Scenario**: A user exports a backup file `backup.sshm` that is lost or leaked.
* **Protection**:
  * `sshm vault export` requires a separate user passphrase and produces an AES-256-GCM encrypted envelope (`SSHMEXPORT`).
  * Plaintext export of credentials is intentionally not supported.

---

## 3. Security Boundaries & Limitations

### What SSHM Cannot Protect Against:
1. **Compromised Operating System Kernel / Root Compromise**: If an attacker has root or kernel access, they can inspect process memory, install rootkits, or hook system calls.
2. **Keyloggers**: If malicious software records keyboard input, passphrases typed into the terminal can be intercepted at the OS level.
3. **Debugger / Memory Inspection**: A process running with the user's privileges and `ptrace` capabilities could inspect application memory while the process is active. To minimize exposure, SSHM zeroes sensitive buffers (`ZeroBytes()`) as soon as operations complete.

---

## 4. Reporting Security Vulnerabilities

If you discover a security vulnerability in SSHM, please report it privately by opening a security advisory on GitHub or emailing the maintainers. Do not disclose vulnerabilities in public issues.

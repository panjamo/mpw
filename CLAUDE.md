# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MPW is a Rust CLI password manager that generates deterministic passwords using the Master Password algorithm. It features secure credential storage, clipboard integration, website auto-opening, and site data management via JSON configuration.

## Build and Development Commands

```bash
# Build the project (debug)
cargo build

# Build optimized release version
cargo build --release

# Check compilation without building
cargo check

# Run the application
cargo run -- <site_name>

# Clean build artifacts
cargo clean
```

## Architecture

### Core Components

- **Main Application** (`src/main.rs`): Command-line interface, credential management, and password generation workflow
- **Windows Credentials** (`src/win_creds.rs`): Windows-specific credential storage functionality (currently unused based on main.rs implementation)

### Key Data Structures

- **SiteEntry**: JSON configuration structure for site data loaded from `main.json`
- **Credentials**: Username/password storage structure
- **EncryptedCredentials**: AES-256-GCM encrypted credential storage for backup files

### Credential Storage System

The application uses a dual-tier credential storage approach:
1. **Primary**: System keyring (Windows Credential Manager)
2. **Fallback**: Machine-encrypted local file (`.mpw_credentials`) using AES-256-GCM

### Password Generation Flow

1. Load site data from `main.json` (if available)
2. Resolve credentials (keyring → encrypted file → prompt)
3. Generate password using Master Password algorithm via `rusterpassword` crate
4. Handle username/clipboard operations and website opening
5. Display identicon for verification

### Site Data Format

The `main.json` file contains an array of site entries with password templates, counters, and user information. The `userName` field supports a special format: `username @@ website_url @@ comment`.

## Key Dependencies

- **rusterpassword**: Master Password algorithm implementation
- **clap**: Command-line parsing with completion generation support
- **keyring**: System credential storage (version 2.3.2 for reliability)
- **aes-gcm**: AES-256-GCM encryption for local backup files
- **arboard**: Cross-platform clipboard operations
- **webbrowser**: Website opening functionality

## Debug and Testing Features

- `--force-keyring-fail`: Forces use of encrypted backup file storage for testing
- `--setup`: Interactive credential management mode
- Debug output shows argument parsing and credential resolution process

## File Locations

- Configuration: `main.json` (same directory as executable)
- Encrypted backup: `.mpw_credentials` (same directory as executable)
- Shell completions: Generated via `--generate-completion` for bash, fish, powershell, zsh, elvish
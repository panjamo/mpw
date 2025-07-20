# MPW - Master Password CLI Tool

A command-line password manager that generates secure, deterministic passwords based on the Master Password algorithm. This tool reads site configuration data from a JSON file and provides enhanced workflow features including clipboard integration and automatic website opening.

## Features

- **Deterministic Password Generation**: Generates the same password every time for the same inputs
- **Multiple Password Templates**: Support for various password types (long, short, basic, PIN, medium, maximum)
- **Site Data Integration**: Loads site configuration from `main.json` file
- **Clipboard Integration**: Automatically copies usernames and passwords to clipboard
- **Website Auto-opening**: Opens websites in your default browser
- **Secure Credential Storage**: Dual storage system with Windows Credential Manager and machine-encrypted local files
- **Regex Search**: Search through site entries using regular expressions
- **Interactive Setup**: Comprehensive credential management interface

## Installation

1. Build from source:
   ```bash
   cargo build --release
   ```

2. The binary will be created in `target/release/mpw` (or `mpw.exe` on Windows)

3. Ensure the `main.json` configuration file is in the same directory as the binary

## Usage

### Basic Password Generation

```bash
mpw <site_name> [OPTIONS]
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `<site_name>` | | Site name (required positional argument) |
| `--template` | `-t` | Password template: `long`, `short`, `basic`, `pin`, `medium`, `maximum` |
| `--password` | `-p` | Master password (if not using stored credentials) |
| `--user` | `-n` | Username (if not using stored credentials) |
| `--counter` | `-c` | Counter for password generation (default: 1) |
| `--regex` | `-r` | Search pattern to find matching entries |
| `--setup` | | Interactive credential management mode |

### Examples

#### Generate password for a site
```bash
mpw github
```

#### Generate password with specific template
```bash
mpw github --template short
```

#### Generate password with custom counter
```bash
mpw github --counter 2
```

#### Search for sites matching a pattern
```bash
mpw --regex "amazon"
mpw --regex ".*\.com"
```

#### Interactive credential management
```bash
mpw --setup
```

## Credential Management

### Interactive Setup Mode

The `--setup` option provides an interactive menu for comprehensive credential management:

```bash
$ mpw --setup
=== MPW Credential Management ===
1. Change default credentials
2. View current credentials
3. Clear stored credentials
4. Exit

Choose an option (1-4):
```

#### Available Options:

1. **Change default credentials**: Update your stored username and master password
2. **View current credentials**: Display current stored credentials (password hidden)
3. **Clear stored credentials**: Remove all stored credentials with confirmation
4. **Exit**: Exit the setup mode

#### Example Usage:

```bash
$ mpw --setup
=== MPW Credential Management ===
1. Change default credentials
2. View current credentials
3. Clear stored credentials
4. Exit

Choose an option (1-4): 1

--- Change Default Credentials ---
New default username: user@example.com
New default master password: [hidden input]
✓ Credentials updated in keyring.
✓ Encrypted credentials saved to local file.
✓ Default credentials updated successfully.

Choose an option (1-4): 2

--- Current Credentials ---
Username: user@example.com
Password: [hidden]
Source: Windows Credential Manager
Backup: Encrypted local file also available

Choose an option (1-4): 4
Goodbye!
```

## Configuration

### Site Data (`main.json`)

The tool reads site configuration from a `main.json` file located in the same directory as the binary. This file contains an array of site entries with the following structure:

```json
[
  {
    "algorithmVersion": "V1",
    "category": "Provider",
    "siteName": "github",
    "userName": "user@example.com @@ https://github.com @@ Development platform",
    "passwordType": "GeneratedLong",
    "siteCounter": 1,
    "lastUsed": 1674400026673,
    "lastChange": 1418208324000,
    "notes": "Development account",
    "customFields": null,
    "questions": null,
    "generatedUserName": false,
    "passwordVariant": "Password"
  }
]
```

### Username Format

The `userName` field supports a special format with multiple parts separated by ` @@ `:

```
username @@ website_url @@ comment
```

For example:
```
user@example.com @@ https://github.com @@ Development platform
```

This allows the tool to:
1. Copy the username to clipboard
2. Open the website automatically
3. Store additional comments

### Password Templates

| Template | Description |
|----------|-------------|
| `long` / `GeneratedLong` | Long alphanumeric password with symbols |
| `short` / `GeneratedShort` | Short alphanumeric password |
| `basic` / `GeneratedBasic` | Basic alphanumeric password |
| `pin` / `GeneratedPIN` | Numeric PIN |
| `medium` / `GeneratedMedium` | Medium length password |
| `maximum` / `GeneratedMaximum` | Maximum security password |

## Workflow

When generating a password for a site with stored data:

1. **Username Handling**: Extracts username from the site data
2. **Clipboard Operations**: 
   - Copies username to clipboard first
   - Opens website if URL is provided
   - Waits 1 second for clipboard operations
   - Copies generated password to clipboard
3. **Visual Feedback**: Shows checkmarks (✓) for successful operations

### Credential Storage

The tool uses a dual storage system for maximum reliability and security:

1. **Primary: Windows Credential Manager** (or system keyring on other platforms)
   - Credentials stored securely in the system's native credential store
   - Accessed through the Windows Credential Manager interface
   - Fully integrated with Windows security infrastructure

2. **Fallback: Machine-Encrypted Local File** (`.mpw_credentials`)
   - Located in the same directory as the executable
   - Encrypted using AES-256-GCM with machine-specific key
   - Encryption key derived from Windows Machine GUID (or Linux machine-id/hostname)
   - Cannot be decrypted on different machines
   - Provides backup when system keyring is unavailable

3. **Storage Priority**:
   - Checks Windows Credential Manager first
   - Falls back to encrypted local file if keyring unavailable
   - Prompts for new credentials if neither exists
   - Always maintains both storage methods when possible

4. **Security Features**:
   - Machine-specific encryption prevents credential theft
   - AES-256-GCM provides authenticated encryption
   - Unique nonces prevent replay attacks
   - No plaintext credentials stored on disk

## Security Considerations

- **Master Password Handling**: Uses secure strings (`SecStr`) to protect in-memory credentials
- **Dual Storage System**: Primary storage in Windows Credential Manager with encrypted local backup
- **Machine-Specific Encryption**: Local files encrypted with machine GUID, preventing cross-machine access
- **Authenticated Encryption**: AES-256-GCM prevents tampering and ensures data integrity
- **No Plaintext Storage**: Credentials never stored in plaintext on disk
- **Binary Optimization**: Debug information stripped and optimized for minimal attack surface

## Dependencies

- **rusterpassword**: Master Password algorithm implementation
- **clap**: Command-line argument parsing
- **keyring**: System keyring/credential manager integration
- **aes-gcm**: AES-256-GCM encryption for local credential storage
- **winreg**: Windows registry access for Machine GUID (Windows only)
- **sha2**: SHA-256 hashing for key derivation
- **base64**: Base64 encoding for encrypted data storage
- **arboard**: Clipboard operations
- **webbrowser**: Website opening functionality
- **regex**: Pattern matching for search
- **serde**: JSON serialization/deserialization

## Building

The project uses optimized release settings:
- Link-time optimization (LTO)
- Stripped debug symbols
- Minimal code generation units
- Size optimization (`opt-level = "z"`)

```bash
cargo build --release
```

## Error Handling

The tool provides informative error messages for:
- Missing site data
- Invalid regex patterns
- Clipboard operation failures
- Credential management issues
- File I/O errors

## License

This project uses the Master Password algorithm and related libraries. Please refer to the individual dependency licenses for more information.
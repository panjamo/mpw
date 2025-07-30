# MPW - Master Password CLI Tool

A command-line password manager that generates secure, deterministic passwords based on the Master Password algorithm. This tool reads site configuration data from a JSON file and provides enhanced workflow features including clipboard integration and automatic website opening.

## Features

- **Deterministic Password Generation**: Generates the same password every time for the same inputs
- **Multiple Password Templates**: Support for various password types (long, short, basic, PIN, medium, maximum)
- **Site Data Integration**: Loads site configuration from `main.json` file
- **Clipboard Integration**: Automatically copies usernames and passwords to clipboard
- **Website Auto-opening**: Opens websites in your default browser
- **Secure Credential Storage**: Prioritized credential storage in Windows Credential Manager with optional encrypted backup
- **Enhanced Credential Reliability**: Thorough verification of keyring storage with smart fallback system
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
| `--force-keyring-fail` | | Force keyring to fail (for testing backup file creation) |
| `--generate-completion` | | Generate shell completion script (value: bash, elvish, fish, powershell, zsh) |

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
```

### Shell Completion

Generate tab completion scripts for various shells:

```bash
# Bash
mpw --generate-completion bash > mpw_completion.bash

# Zsh
mpw --generate-completion zsh > _mpw

# Fish
mpw --generate-completion fish > mpw.fish

# PowerShell
mpw --generate-completion powershell > mpw_completion.ps1

# Elvish
mpw --generate-completion elvish > mpw.elv
```

Then in your shell's configuration, source the appropriate file to enable tab completion.

For PowerShell:

```powershell
# Add this to your PowerShell profile (~\Documents\PowerShell\Microsoft.PowerShell_profile.ps1)
. "C:\path\to\mpw_completion.ps1"
```

To find your PowerShell profile location:

```powershell
echo $PROFILE
```

If the profile doesn't exist yet, you can create it:

```powershell
New-Item -Path $PROFILE -Type File -Force
```

For Bash (add to .bashrc):
```bash
source /path/to/mpw_completion.bash
```

For Zsh (place _mpw in a directory in your fpath):
```bash
# Example - add to .zshrc
fpath=(/path/to/completion/directory $fpath)
compinit
```

For Fish (place in ~/.config/fish/completions/):
```bash
ln -s /path/to/mpw.fish ~/.config/fish/completions/
```

For Elvish (add to rc.elv):
```bash
eval (cat /path/to/mpw.elv)
```

1. Change default credentials
2. View current credentials
3. Clear stored credentials
4. Exit

Choose an option (1-4): 1

--- Change Default Credentials ---
New default username: user@example.com
New default master password: [hidden input]
✓ Credentials updated in keyring.
✓ Credentials verified successfully.
✓ Keyring storage working correctly, no backup file needed.
✓ Default credentials updated successfully.

Choose an option (1-4): 2

--- Current Credentials ---
Username: user@example.com
Password: [hidden]
Source: Windows Credential Manager

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

The tool uses a smart credential storage system for maximum security and reliability:

1. **Primary: Windows Credential Manager** (or system keyring on other platforms)
   - Credentials stored securely in the system's native credential store
   - Accessed through the Windows Credential Manager interface
   - Fully integrated with Windows security infrastructure
   - Robust verification after storage to ensure reliability
   - Detailed error reporting for troubleshooting

2. **Fallback: Machine-Encrypted Local File** (`.mpw_credentials`)
   - Created ONLY if Windows Credential Manager fails
   - Located in the same directory as the executable
   - Encrypted using AES-256-GCM with machine-specific key
   - Encryption key derived from Windows Machine GUID (or Linux machine-id/hostname)
   - Cannot be decrypted on different machines
   - Automatically removed when Credential Manager works properly

3. **Storage Priority**:
   - Always attempts to use Windows Credential Manager first
   - Falls back to encrypted local file ONLY if keyring unavailable
   - Prompts for new credentials if neither exists
   - Optimized to minimize credential duplication
   - Maintains only one storage method when possible

4. **Security Features**:
   - Machine-specific encryption prevents credential theft
   - AES-256-GCM provides authenticated encryption
   - Unique nonces prevent replay attacks
   - No plaintext credentials stored on disk

## Security Considerations

- **Master Password Handling**: Uses secure strings (`SecStr`) to protect in-memory credentials
- **Smart Storage System**: Primary storage in Windows Credential Manager with encrypted local backup only when needed
- **Machine-Specific Encryption**: Local files encrypted with machine GUID, preventing cross-machine access
- **Authenticated Encryption**: AES-256-GCM prevents tampering and ensures data integrity
- **No Plaintext Storage**: Credentials never stored in plaintext on disk
- **Binary Optimization**: Debug information stripped and optimized for minimal attack surface

## Dependencies

- **rusterpassword**: Master Password algorithm implementation
- **clap**: Command-line argument parsing
- **keyring**: System keyring/credential manager integration (version 2.3.2+) with enhanced reliability
- **aes-gcm**: AES-256-GCM encryption for local credential storage
- **winreg**: Windows registry access for Machine GUID (Windows only)
- **sha2**: SHA-256 hashing for key derivation
- **base64**: Base64 encoding for encrypted data storage
- **arboard**: Clipboard operations
- **webbrowser**: Website opening functionality
- **regex**: Pattern matching for search
- **serde**: JSON serialization/deserialization

## Debugging Credential Storage

For testing or diagnosing issues with credential storage:

### Force Keyring Failure

The `--force-keyring-fail` flag can be used to deliberately bypass the Windows Credential Manager:

```bash
mpw --setup --force-keyring-fail
```

This forces the application to use the encrypted backup file storage, which is useful for:
- Testing the fallback mechanism
- Diagnosing Windows Credential Manager issues
- Using the tool when Windows security policies restrict credential manager access

### Verbose Logging

The application provides detailed diagnostic messages about credential operations:
- Success/failure of keyring operations
- Verification of stored credentials
- Creation and management of backup files
- Source of retrieved credentials

Example output:
```
Attempting to retrieve credentials from keyring...
✓ Successfully created keyring entry objects
✓ Successfully retrieved credentials from keyring
✓ Credential verification successful
✓ Keyring storage working correctly, no backup file needed.
```

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
- Keyring access failures
- Backup file creation/retrieval problems

## Troubleshooting

### Windows Credential Manager Issues

If you experience problems with credential storage:

1. **Check Access Permissions**: Ensure your user has access to Windows Credential Manager
2. **Run in Admin Mode**: Some systems may require elevated privileges
3. **Use Backup Mode**: Use `--force-keyring-fail` to rely on the encrypted backup file
4. **Check Diagnostics**: Review the detailed messages for specific error information
5. **Verify Installation**: Check that keyring version 2.3.2+ is being used for best compatibility

### Backup File Issues

If backup file storage isn't working:

1. **Check Write Permissions**: Ensure the application can write to its directory
2. **Machine GUID Access**: The application needs registry read access to get the machine GUID
3. **Look for Error Details**: The application shows specific error messages for encryption/decryption problems

## License

This project uses the Master Password algorithm and related libraries. Please refer to the individual dependency licenses for more information.
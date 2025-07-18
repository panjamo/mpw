# MPW - Master Password CLI Tool

A command-line password manager that generates secure, deterministic passwords based on the Master Password algorithm. This tool reads site configuration data from a JSON file and provides enhanced workflow features including clipboard integration and automatic website opening.

## Features

- **Deterministic Password Generation**: Generates the same password every time for the same inputs
- **Multiple Password Templates**: Support for various password types (long, short, basic, PIN, medium, maximum)
- **Site Data Integration**: Loads site configuration from `main.json` file
- **Clipboard Integration**: Automatically copies usernames and passwords to clipboard
- **Website Auto-opening**: Opens websites in your default browser
- **Credential Management**: Stores master credentials securely using system keyring or local file
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
mpw --site <site_name> [OPTIONS]
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--site` | `-s` | Site name (required for password generation) |
| `--template` | `-t` | Password template: `long`, `short`, `basic`, `pin`, `medium`, `maximum` |
| `--password` | `-p` | Master password (if not using stored credentials) |
| `--user` | `-n` | Username (if not using stored credentials) |
| `--counter` | `-c` | Counter for password generation (default: 1) |
| `--regex` | `-r` | Search pattern to find matching entries |
| `--setup` | | Interactive credential management mode |

### Examples

#### Generate password for a site
```bash
mpw --site github
```

#### Generate password with specific template
```bash
mpw --site github --template short
```

#### Generate password with custom counter
```bash
mpw --site github --counter 2
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
✓ Credentials saved to local file.
✓ Default credentials updated successfully.

Choose an option (1-4): 2

--- Current Credentials ---
Username: user@example.com
Password: [hidden]
Source: Local file

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

The tool manages master credentials through multiple methods:

1. **System Keyring**: Stores credentials securely using the system's keyring service
2. **Local File**: Falls back to `.mpw_credentials` file in the current directory
3. **Interactive Setup**: Prompts for credentials if none are found

The local credentials file (`.mpw_credentials`) stores:
```json
{
  "username": "your_username",
  "password": "your_master_password"
}
```

## Security Considerations

- Master passwords are handled using secure strings (`SecStr`)
- Credentials are stored in system keyring when available
- Local credential files should be protected with appropriate file permissions
- The tool strips debug information and optimizes for minimal binary size

## Dependencies

- **rusterpassword**: Master Password algorithm implementation
- **clap**: Command-line argument parsing
- **keyring**: Secure credential storage
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
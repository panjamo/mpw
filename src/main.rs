use keyring::Entry;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use arboard::Clipboard;
use base64::{Engine as _, engine::general_purpose};
use clap::{ArgAction, Parser};
use regex::Regex;
use rusterpassword::*;
use secstr::SecStr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
use winreg::RegKey;
#[cfg(windows)]
use winreg::enums::*;

#[derive(Debug, Deserialize, Serialize)]
struct SiteEntry {
    #[serde(rename = "algorithmVersion")]
    algorithm_version: Option<String>,
    #[serde(rename = "category")]
    category: Option<String>,
    #[serde(rename = "customFields")]
    custom_fields: Option<serde_json::Value>,
    #[serde(rename = "generatedUserName")]
    generated_user_name: Option<bool>,
    #[serde(rename = "lastChange")]
    last_change: Option<u64>,
    #[serde(rename = "lastUsed")]
    last_used: Option<u64>,
    #[serde(rename = "notes")]
    notes: Option<String>,
    #[serde(rename = "passwordType")]
    password_type: String,
    #[serde(rename = "passwordVariant")]
    password_variant: Option<String>,
    #[serde(rename = "questions")]
    questions: Option<serde_json::Value>,
    #[serde(rename = "siteCounter")]
    site_counter: u32,
    #[serde(rename = "siteName")]
    site_name: String,
    #[serde(rename = "userName")]
    user_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct EncryptedCredentials {
    data: String,
    nonce: String,
}

#[cfg(windows)]
fn get_machine_guid() -> Result<String, Box<dyn std::error::Error>> {
    println!("Retrieving Windows machine GUID...");
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let crypto_key = match hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
        Ok(key) => {
            println!("✓ Successfully opened Cryptography registry key");
            key
        },
        Err(e) => {
            println!("⚠ Error opening Cryptography registry key: {}", e);
            return Err(Box::new(e));
        }
    };
    
    let machine_guid: String = match crypto_key.get_value("MachineGuid") {
        Ok(guid) => {
            println!("✓ Successfully retrieved MachineGuid");
            guid
        },
        Err(e) => {
            println!("⚠ Error retrieving MachineGuid: {}", e);
            return Err(Box::new(e));
        }
    };
    
    Ok(machine_guid)
}

#[cfg(not(windows))]
fn get_machine_guid() -> Result<String, Box<dyn std::error::Error>> {
    // Fallback for non-Windows: use hostname + /etc/machine-id if available
    use std::process::Command;

    // Try /etc/machine-id first (systemd)
    if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
        return Ok(machine_id.trim().to_string());
    }

    // Fallback to hostname
    let output = Command::new("hostname").output()?;
    let hostname = String::from_utf8(output.stdout)?;
    Ok(hostname.trim().to_string())
}

fn derive_key_from_machine_guid() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let machine_guid = get_machine_guid()?;
    let mut hasher = Sha256::new();
    hasher.update(machine_guid.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

fn encrypt_credentials(
    username: &str,
    password: &str,
) -> Result<EncryptedCredentials, Box<dyn std::error::Error>> {
    let key = derive_key_from_machine_guid()?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let credentials = Credentials {
        username: username.to_string(),
        password: password.to_string(),
    };
    let plaintext = serde_json::to_string(&credentials)?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    Ok(EncryptedCredentials {
        data: general_purpose::STANDARD.encode(ciphertext),
        nonce: general_purpose::STANDARD.encode(nonce),
    })
}

fn decrypt_credentials(
    encrypted: &EncryptedCredentials,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let key = derive_key_from_machine_guid()?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let ciphertext = general_purpose::STANDARD.decode(&encrypted.data)?;
    let nonce_bytes = general_purpose::STANDARD.decode(&encrypted.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    let credentials: Credentials = serde_json::from_slice(&plaintext)?;

    Ok((credentials.username, credentials.password))
}

#[derive(Parser)]
#[command(name = "mpw-rs")]
#[command(about = "A CLI tool for generating passwords using the rusterpassword crate")]
struct Args {
    #[arg(help = "Site name")]
    site: Option<String>,

    #[arg(
        long,
        help = "Force keyring to fail (for testing backup file creation)",
        action = ArgAction::SetTrue
    )]
    force_keyring_fail: bool,

    #[arg(
        short,
        long,
        help = "Password template. Available: long, short, basic, pin, medium, maximum"
    )]
    template: Option<String>,

    #[arg(short, long, help = "Master password")]
    password: Option<String>,

    #[arg(short = 'n', long, help = "User name")]
    user: Option<String>,

    #[arg(short, long, help = "Counter for password generation")]
    counter: Option<u32>,

    #[arg(
        short = 'r',
        long,
        help = "Regex search pattern to find matching entries"
    )]
    regex: Option<String>,

    #[arg(
        long,
        help = "Interactive setup mode for credential management",
        action = ArgAction::SetTrue
    )]
    setup: bool,
}

fn get_main_json_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let folder = std::env::current_exe()?
        .parent()
        .ok_or("Could not get binary folder")?
        .to_path_buf();
    Ok(folder.join("main.json"))
}

fn get_credentials_file_path() -> PathBuf {
    let mut path = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("mpw.exe"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    path.push(".mpw_credentials");
    path
}

fn save_encrypted_credentials(
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = encrypt_credentials(username, password)?;
    let content = serde_json::to_string(&encrypted)?;
    fs::write(get_credentials_file_path(), content)?;
    Ok(())
}

fn load_encrypted_credentials() -> Result<(String, String), Box<dyn std::error::Error>> {
    let creds_path = get_credentials_file_path();
    println!("Checking for encrypted credentials file at {:?}", creds_path);
    
    if !creds_path.exists() {
        println!("⚠ No encrypted credentials file found at {:?}", creds_path);
        return Err("No encrypted credentials file found".into());
    }

    println!("Reading encrypted credentials file...");
    let content = fs::read_to_string(&creds_path)?;
    let encrypted: EncryptedCredentials = serde_json::from_str(&content)?;
    println!("✓ Encrypted credentials file parsed successfully");
    
    println!("Attempting to decrypt credentials...");
    let result = decrypt_credentials(&encrypted);
    if result.is_ok() {
        println!("✓ Credentials decrypted successfully");
    } else {
        println!("⚠ Failed to decrypt credentials");
    }
    result
}

// Display current credentials source in a friendly way
fn get_credentials_source_description(source_type: &str) -> &'static str {
    match source_type {
        "keyring" => "Windows Credential Manager",
        "file" => "Encrypted local file",
        _ => "Unknown source"
    }
}

// Check if file exists without reading it
fn check_credentials_file_exists() -> bool {
    get_credentials_file_path().exists()
}

fn load_site_data(site_name: &str) -> Result<Option<SiteEntry>, Box<dyn std::error::Error>> {
    let main_json_path = get_main_json_path()?;

    if main_json_path.exists() {
        let content = fs::read_to_string(main_json_path)?;
        let entries: Vec<SiteEntry> = serde_json::from_str(&content)?;

        for entry in entries {
            if entry.site_name == site_name {
                return Ok(Some(entry));
            }
        }
    }
    Ok(None)
}

fn search_entries_by_regex(pattern: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let main_json_path = get_main_json_path()?;

    if !main_json_path.exists() {
        return Err("main.json file not found".into());
    }

    let content = fs::read_to_string(main_json_path)?;
    let entries: Vec<SiteEntry> = serde_json::from_str(&content)?;
    let regex = Regex::new(pattern)?;

    let mut matching_sites = Vec::new();

    for entry in entries {
        let mut matched = false;

        // Check all string fields
        if let Some(ref algorithm_version) = entry.algorithm_version {
            if regex.is_match(algorithm_version) {
                matched = true;
            }
        }

        if let Some(ref category) = entry.category {
            if regex.is_match(category) {
                matched = true;
            }
        }

        if let Some(ref notes) = entry.notes {
            if regex.is_match(notes) {
                matched = true;
            }
        }

        if regex.is_match(&entry.password_type) {
            matched = true;
        }

        if let Some(ref password_variant) = entry.password_variant {
            if regex.is_match(password_variant) {
                matched = true;
            }
        }

        if regex.is_match(&entry.site_name) {
            matched = true;
        }

        if let Some(ref user_name) = entry.user_name {
            if regex.is_match(user_name) {
                matched = true;
            }
        }

        // Check numeric fields as strings
        if regex.is_match(&entry.site_counter.to_string()) {
            matched = true;
        }

        if let Some(last_change) = entry.last_change {
            if regex.is_match(&last_change.to_string()) {
                matched = true;
            }
        }

        if let Some(last_used) = entry.last_used {
            if regex.is_match(&last_used.to_string()) {
                matched = true;
            }
        }

        // Check JSON fields if they exist
        if let Some(ref custom_fields) = entry.custom_fields {
            if let Ok(json_str) = serde_json::to_string(custom_fields) {
                if regex.is_match(&json_str) {
                    matched = true;
                }
            }
        }

        if let Some(ref questions) = entry.questions {
            if let Ok(json_str) = serde_json::to_string(questions) {
                if regex.is_match(&json_str) {
                    matched = true;
                }
            }
        }

        if matched {
            matching_sites.push(entry.site_name);
        }
    }

    Ok(matching_sites)
}

fn password_type_to_template(password_type: &str) -> &'static [&'static str] {
    match password_type {
        "GeneratedLong" => TEMPLATES_LONG,
        "GeneratedShort" => TEMPLATES_SHORT,
        "GeneratedBasic" => TEMPLATES_BASIC,
        "GeneratedPIN" => TEMPLATES_PIN,
        "GeneratedMedium" => TEMPLATES_MEDIUM,
        "GeneratedMaximum" => TEMPLATES_MAXIMUM,
        _ => TEMPLATES_LONG,
    }
}

fn parse_user_name(user_name: &str) -> (String, Option<String>, Option<String>) {
    let parts: Vec<&str> = user_name.split(" @@ ").collect();
    match parts.len() {
        1 => (parts[0].to_string(), None, None),
        2 => (parts[0].to_string(), Some(parts[1].to_string()), None),
        3 => (
            parts[0].to_string(),
            Some(parts[1].to_string()),
            Some(parts[2].to_string()),
        ),
        _ => {
            // Handle case with more than 3 parts - join the rest as comment
            let username = parts[0].to_string();
            let website = Some(parts[1].to_string());
            let comment = Some(parts[2..].join(" @@ "));
            (username, website, comment)
        }
    }
}

fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(text)?;
    Ok(())
}

fn open_website(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    if url.starts_with("http") {
        webbrowser::open(url)?;
    }
    Ok(())
}

fn setup_credentials() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== MPW Credential Management ===");
    println!("1. Change default credentials");
    println!("2. View current credentials");
    println!("3. Clear stored credentials");
    println!("4. Exit");

    loop {
        print!("Choose an option (1-4): ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                println!("\n--- Change Default Credentials ---");
                print!("New default username: ");
                io::stdout().flush()?;
                let mut user = String::new();
                io::stdin().read_line(&mut user)?;
                let user = user.trim().to_string();

                let password = rpassword::prompt_password("New default master password: ")?;

                // Update keyring
                let mut keyring_ok = false;
                
                // Check if we should force keyring to fail
                let args = Args::parse();
                if args.force_keyring_fail {
                    println!("⚠ Keyring access deliberately disabled by --force-keyring-fail flag");
                } else if let (Ok(user_entry), Ok(password_entry)) = (
                    Entry::new("mpw", "default_user"),
                    Entry::new("mpw", "default_password"),
                ) {
                    let user_result = user_entry.set_password(&user);
                    let pass_result = password_entry.set_password(&password);
                    
                    if user_result.is_ok() && pass_result.is_ok() {
                        println!("✓ Credentials updated in keyring.");
                        
                        // Verify credentials were saved correctly
                        match (user_entry.get_password(), password_entry.get_password()) {
                            (Ok(saved_user), Ok(saved_pass)) => {
                                if saved_user == user && saved_pass == password {
                                    println!("✓ Credentials verified successfully.");
                                    keyring_ok = true;
                                } else {
                                    println!("⚠ Credential verification failed - saved values don't match.");
                                    println!("  Expected username: {}, Got: {}", user, saved_user);
                                    println!("  Password match: {}", saved_pass == password);
                                }
                            },
                            (Err(e), _) => println!("⚠ Error verifying username: {}", e),
                            (_, Err(e)) => println!("⚠ Error verifying password: {}", e),
                        }
                    } else {
                        if let Err(e) = user_result {
                            println!("⚠ Could not store username in keyring: {}", e);
                        }
                        if let Err(e) = pass_result {
                            println!("⚠ Could not store password in keyring: {}", e);
                        }
                    }
                } else {
                    println!("⚠ Could not create keyring entries.");
                }

                // Only update encrypted file storage if keyring failed
                
                if !keyring_ok {
                    println!("Keyring storage not working, saving backup file...");
                    if let Err(e) = save_encrypted_credentials(&user, &password) {
                        println!("⚠ Could not save encrypted backup file: {}", e);
                    } else {
                        println!("✓ Encrypted credentials saved to local file.");
                    }
                } else {
                    println!("✓ Keyring storage working correctly, no backup file needed.");
                    
                    // Remove any existing backup file
                    let creds_path = get_credentials_file_path();
                    if creds_path.exists() {
                        if let Err(e) = fs::remove_file(&creds_path) {
                            println!("⚠ Could not remove old backup file: {}", e);
                        } else {
                            println!("✓ Old backup file removed.");
                        }
                    }
                }

                println!("✓ Default credentials updated successfully.\n");
            }
            "2" => {
                println!("\n--- Current Credentials ---");
                let _file_exists = check_credentials_file_exists();
                let mut found_credentials = false;

                // Check Windows Credential Manager first
                if let (Ok(user_entry), Ok(_)) = (
                    Entry::new("mpw", "default_user"),
                    Entry::new("mpw", "default_password"),
                ) {
                    if let Ok(user) = user_entry.get_password() {
                        if !user.is_empty() {
                            println!("Username: {}", user);
                            println!("Password: [hidden]");
                            println!("Source: {}", get_credentials_source_description("keyring"));
                            found_credentials = true;
                        }
                    }
                }

                // Check encrypted local file
                if let Ok((user, _)) = load_encrypted_credentials() {
                    if !found_credentials {
                        println!("Username: {}", user);
                        println!("Password: [hidden]");
                        println!("Source: {}", get_credentials_source_description("file"));
                    } else {
                        println!("Backup: Encrypted local file also available");
                    }
                    found_credentials = true;
                }

                if !found_credentials {
                    println!("No credentials found.");
                }
                println!();
            }
            "3" => {
                println!("\n--- Clear Stored Credentials ---");
                print!("Are you sure? This will remove all stored credentials (y/N): ");
                io::stdout().flush()?;
                let mut confirm = String::new();
                io::stdin().read_line(&mut confirm)?;

                if confirm.trim().to_lowercase() == "y" {
                    // Clear keyring entries
                    if let (Ok(user_entry), Ok(pass_entry)) = (
                        Entry::new("mpw", "default_user"),
                        Entry::new("mpw", "default_password"),
                    ) {
                        let user_result = user_entry.delete_password();
                        let pass_result = pass_entry.delete_password();
                        
                        if user_result.is_ok() && pass_result.is_ok() {
                            println!("✓ Cleared keyring credentials.");
                        } else {
                            println!("⚠ Warning: Could not completely clear keyring credentials.");
                            if let Err(e) = user_result {
                                println!("  Username error: {}", e);
                            }
                            if let Err(e) = pass_result {
                                println!("  Password error: {}", e);
                            }
                        }
                    }

                    // Always clear encrypted backup file when requested
                    let creds_path = get_credentials_file_path();
                    if creds_path.exists() {
                        if let Err(e) = fs::remove_file(&creds_path) {
                            println!("⚠ Could not remove encrypted credentials file: {}", e);
                        } else {
                            println!("✓ Removed encrypted credentials file.");
                        }
                    } else {
                        println!("ℹ No backup file found to remove.");
                    }

                    println!("✓ All stored credentials cleared.\n");
                } else {
                    println!("Operation cancelled.\n");
                }
            }
            "4" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("Invalid option. Please choose 1-4.\n");
            }
        }
    }

    Ok(())
}

// Try to get credentials from backup file or prompt user
fn try_backup_file_or_prompt() -> Result<(String, String), Box<dyn std::error::Error>> {
    // Try backup file first
    if let Ok((user, password)) = load_encrypted_credentials() {
        println!("✓ Retrieved credentials from backup file");
        return Ok((user, password));
    }
    
    // No stored credentials found, prompt user
    println!("No stored credentials found. Please set up default credentials:");
    print!("Default username: ");
    io::stdout().flush()?;
    let mut user = String::new();
    io::stdin().read_line(&mut user)?;
    let user = user.trim().to_string();

    let password = rpassword::prompt_password("Default master password: ")?;
    
    Ok((user, password))
}

fn get_or_store_credentials() -> Result<(String, String), Box<dyn std::error::Error>> {
    // Check if we should force keyring to fail
    let args = Args::parse();
    if args.force_keyring_fail {
        println!("\n⚠ Keyring access deliberately disabled by --force-keyring-fail flag");
        return try_backup_file_or_prompt();
    }

    println!("\nAttempting to retrieve credentials from keyring...");
    
    let mut keyring_tried = false;
    
    // Try Windows Credential Manager first
    if let (Ok(user_entry), Ok(password_entry)) = (
        Entry::new("mpw", "default_user"),
        Entry::new("mpw", "default_password"),
    ) {
        println!("✓ Successfully created keyring entry objects");
        keyring_tried = true;
        
        match (user_entry.get_password(), password_entry.get_password()) {
            (Ok(user), Ok(password)) => {
                if !user.is_empty() && !password.is_empty() {
                    println!("✓ Successfully retrieved credentials from keyring");
                    return Ok((user, password));
                } else {
                    println!("⚠ Credentials exist in keyring but are empty");
                }
            },
            (Err(e), _) => {
                println!("⚠ Error retrieving username from keyring: {}", e);
            },
            (_, Err(e)) => {
                println!("⚠ Error retrieving password from keyring: {}", e);
            }
        }
    } else {
        println!("⚠ Could not create keyring entry objects");
    }

    // Try encrypted local file as fallback only if keyring was tried but failed
    if keyring_tried {
        return try_backup_file_or_prompt();
    } else {
        println!("⚠ Keyring not available, and no backup attempted");
    }

    // No stored credentials, prompt for input
    let (user, password) = try_backup_file_or_prompt()?;

    // Try to store in Windows Credential Manager first
    let mut keyring_success = false;
    println!("\nAttempting to store credentials in keyring...");
    
    // Check if we should force keyring to fail
    let args = Args::parse();
    if args.force_keyring_fail {
        println!("⚠ Keyring access deliberately disabled by --force-keyring-fail flag");
    } else if let (Ok(user_entry), Ok(password_entry)) = (
        Entry::new("mpw", "default_user"),
        Entry::new("mpw", "default_password"),
    ) {
        println!("✓ Successfully created keyring entry objects");
        
        let user_result = user_entry.set_password(&user);
        let pass_result = password_entry.set_password(&password);
        
        if user_result.is_ok() && pass_result.is_ok() {
            println!("✓ Credentials stored in keyring");
            
            // Verify the credentials were stored correctly
            match (user_entry.get_password(), password_entry.get_password()) {
                (Ok(stored_user), Ok(stored_pass)) => {
                    if stored_user == user && stored_pass == password {
                        println!("✓ Credential verification successful");
                        keyring_success = true;
                    } else {
                        println!("⚠ Credential verification failed - stored values don't match");
                        println!("  Username match: {}", stored_user == user);
                        println!("  Password match: {}", stored_pass == password);
                    }
                },
                (Err(e), _) => println!("⚠ Error verifying username: {}", e),
                (_, Err(e)) => println!("⚠ Error verifying password: {}", e),
            }
        } else {
            if let Err(e) = user_result {
                println!("⚠ Failed to store username: {}", e);
            }
            if let Err(e) = pass_result {
                println!("⚠ Failed to store password: {}", e);
            }
        }
    } else {
        println!("⚠ Could not create keyring entry objects");
    }

    // Store encrypted backup file only if keyring storage failed
    if !keyring_success {
        println!("Keyring storage failed, saving to backup file...");
        if let Err(e) = save_encrypted_credentials(&user, &password) {
            return Err(format!("Could not store credentials anywhere: {}", e).into());
        } else {
            println!("✓ Encrypted backup file saved.");
        }
    } else {
        // Remove any existing backup file
        let creds_path = get_credentials_file_path();
        if creds_path.exists() {
            if let Err(e) = fs::remove_file(&creds_path) {
                println!("⚠ Could not remove old backup file: {}", e);
            } else {
                println!("✓ Old backup file removed as keyring is working.");
            }
        }
    }

    if !keyring_success {
        println!(
            "⚠ Warning: Could not store in keyring, using encrypted file only."
        );
    }

    Ok((user, password))
}

fn handle_setup_mode() -> Result<(), Box<dyn std::error::Error>> {
    setup_credentials()?;
    Ok(())
}

fn handle_regex_search(regex_pattern: &str) -> Result<(), Box<dyn std::error::Error>> {
    let matching_sites = search_entries_by_regex(regex_pattern)?;
    if matching_sites.is_empty() {
        println!(
            "No entries found matching the regex pattern: {}",
            regex_pattern
        );
    } else {
        println!("Found {} matching entries:", matching_sites.len());
        for site in matching_sites {
            println!("  {}", site);
        }
    }
    Ok(())
}

fn resolve_credentials(
    args_user: Option<String>,
    args_password: Option<String>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    match (args_user, args_password) {
        (Some(u), Some(p)) => Ok((u, p)),
        (user_arg, password_arg) => {
            let (default_user, default_password) = get_or_store_credentials()?;
            Ok((
                user_arg.unwrap_or(default_user),
                password_arg.unwrap_or(default_password),
            ))
        }
    }
}

fn resolve_template_name(args_template: Option<String>, site_data: &Option<SiteEntry>) -> String {
    args_template.unwrap_or_else(|| {
        site_data
            .as_ref()
            .map(|d| d.password_type.clone())
            .unwrap_or_else(|| "GeneratedLong".to_string())
    })
}

fn resolve_template(
    args_template: Option<String>,
    site_data: &Option<SiteEntry>,
) -> &'static [&'static str] {
    let template_str = resolve_template_name(args_template, site_data);

    if let Some(data) = site_data {
        password_type_to_template(&data.password_type)
    } else {
        match template_str.as_str() {
            "long" => TEMPLATES_LONG,
            "short" => TEMPLATES_SHORT,
            "basic" => TEMPLATES_BASIC,
            "pin" => TEMPLATES_PIN,
            "medium" => TEMPLATES_MEDIUM,
            "maximum" => TEMPLATES_MAXIMUM,
            "GeneratedLong" => TEMPLATES_LONG,
            "GeneratedShort" => TEMPLATES_SHORT,
            "GeneratedBasic" => TEMPLATES_BASIC,
            "GeneratedPIN" => TEMPLATES_PIN,
            "GeneratedMedium" => TEMPLATES_MEDIUM,
            "GeneratedMaximum" => TEMPLATES_MAXIMUM,
            _ => {
                eprintln!(
                    "Unknown template: {}. Using 'long' as default.",
                    template_str
                );
                TEMPLATES_LONG
            }
        }
    }
}

fn generate_password(
    user: &str,
    password: &str,
    site_name: &str,
    counter: u32,
    templates: &'static [&'static str],
) -> Result<String, Box<dyn std::error::Error>> {
    let master_pass = SecStr::from(password);
    let master_key = gen_master_key(master_pass.clone(), user)?;
    let site_seed = gen_site_seed(&master_key, site_name, counter)?;
    let password = gen_site_password(&site_seed, templates);
    Ok(String::from_utf8_lossy(password.unsecure()).to_string())
}

fn handle_user_workflow(
    site_data: &Option<SiteEntry>,
    password_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(data) = site_data {
        if let Some(user_name) = &data.user_name {
            let (username, website, _comment) = parse_user_name(user_name);

            copy_to_clipboard(&username)
                .map_err(|e| {
                    eprintln!("Warning: Could not copy username to clipboard: {}", e);
                    e
                })
                .unwrap_or_else(|_| {
                    println!("✓ Username copied to clipboard: {}", username);
                });

            if let Some(url) = &website {
                if url.starts_with("http") {
                    open_website(url)
                        .map_err(|e| {
                            eprintln!("Warning: Could not open website: {}", e);
                            e
                        })
                        .unwrap_or_else(|_| {
                            println!("✓ Opened website: {}", url);
                        });
                }
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    copy_to_clipboard(password_str)
        .map_err(|e| {
            eprintln!("Warning: Could not copy password to clipboard: {}", e);
            e
        })
        .unwrap_or_else(|_| {
            println!("✓ Password copied to clipboard");
        });

    Ok(())
}

fn display_identicon(master_pass: &SecStr, user: &str) {
    let identicon = create_identicon(master_pass, user);
    print!("Identicon: ");
    for value in [
        &identicon.left_arm,
        &identicon.body,
        &identicon.right_arm,
        &identicon.accessory,
    ] {
        print!("{}", value);
    }
    println!(", Color: {}", identicon.color);
}

fn main() {
    let args = Args::parse();
    
    // Debug prints
    println!("[DEBUG] Arguments received:");
    println!("[DEBUG] Site: {:?}", args.site);
    println!("[DEBUG] Template: {:?}", args.template);
    println!("[DEBUG] User: {:?}", args.user);
    println!("[DEBUG] Counter: {:?}", args.counter);
    println!("[DEBUG] Regex: {:?}", args.regex);
    println!("[DEBUG] Setup: {}", args.setup);
    println!("[DEBUG] Force keyring fail: {}", args.force_keyring_fail);

    if args.setup {
        println!("[DEBUG] Entering setup mode");
        if let Err(e) = handle_setup_mode() {
            eprintln!("Error in setup mode: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if let Some(regex_pattern) = args.regex {
        println!("[DEBUG] Handling regex search with pattern: {}", regex_pattern);
        if let Err(e) = handle_regex_search(&regex_pattern) {
            eprintln!("Error searching entries: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let site_name = match args.site {
        Some(site) => {
            println!("[DEBUG] Using site name: {}", site);
            site
        },
        None => {
            eprintln!(
                "Error: Site name is required for password generation. Use --site or --regex option."
            );
            std::process::exit(1);
        }
    };

    let (user, password) = match resolve_credentials(args.user, args.password) {
        Ok(creds) => {
            println!("[DEBUG] Credentials resolved successfully for user: {}", creds.0);
            creds
        },
        Err(e) => {
            eprintln!("Error getting credentials: {}", e);
            std::process::exit(1);
        }
    };

    let site_data = load_site_data(&site_name).unwrap_or_else(|e| {
        eprintln!("Warning: Could not load site data: {}", e);
        None
    });

    let counter = args
        .counter
        .unwrap_or_else(|| site_data.as_ref().map(|d| d.site_counter).unwrap_or(1));

    let template_name = resolve_template_name(args.template.clone(), &site_data);
    let templates = resolve_template(args.template, &site_data);

    // Print site information
    println!("Site: {}", site_name);
    println!("Counter: {}", counter);
    println!("Template: {}", template_name);

    // Print website and comment if available from site data
    if let Some(ref data) = site_data {
        if let Some(ref user_name) = data.user_name {
            let (username, website, comment) = parse_user_name(user_name);
            println!("Username: {}", username);
            if let Some(ref url) = website {
                println!("Website: {}", url);
            }
            if let Some(ref note) = comment {
                println!("Comment: {}", note);
            }
        }
        if let Some(ref notes) = data.notes {
            if !notes.trim().is_empty() {
                println!("Notes: {}", notes);
            }
        }
    }

    let password_str = match generate_password(&user, &password, &site_name, counter, templates) {
        Ok(pwd) => pwd,
        Err(e) => {
            eprintln!("Error generating password: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = handle_user_workflow(&site_data, &password_str) {
        eprintln!("Warning: Error in user workflow: {}", e);
    }

    let master_pass = SecStr::from(password);
    display_identicon(&master_pass, &user);
}

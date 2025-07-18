use arboard::Clipboard;
use clap::{ArgAction, Parser};
use keyring::Entry;
use regex::Regex;
use rusterpassword::*;
use secstr::SecStr;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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

#[derive(Parser)]
#[command(name = "mpw-rs")]
#[command(about = "A CLI tool for generating passwords using the rusterpassword crate")]
struct Args {
    #[arg(short, long, help = "Site name")]
    site: Option<String>,

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

fn load_site_data(site_name: &str) -> Result<Option<SiteEntry>, Box<dyn std::error::Error>> {
    let folder = std::env::current_exe()?
        .parent()
        .ok_or("Could not get binary folder")?
        .to_path_buf();

    if Path::new(&folder.join("main.json")).exists() {
        let content = fs::read_to_string(folder.join("main.json"))?;
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
    if !Path::new("main.json").exists() {
        return Err("main.json file not found".into());
    }

    let content = fs::read_to_string("main.json")?;
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

fn get_credentials_file_path() -> PathBuf {
    let mut path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    path.push(".mpw_credentials");
    path
}

fn load_file_credentials() -> Result<(String, String), Box<dyn std::error::Error>> {
    let creds_path = get_credentials_file_path();
    if creds_path.exists() {
        let content = fs::read_to_string(creds_path)?;
        let creds: Credentials = serde_json::from_str(&content)?;
        Ok((creds.username, creds.password))
    } else {
        Err("No credentials file found".into())
    }
}

fn save_file_credentials(username: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let creds = Credentials {
        username: username.to_string(),
        password: password.to_string(),
    };
    let content = serde_json::to_string(&creds)?;
    fs::write(get_credentials_file_path(), content)?;
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
                if let (Ok(user_entry), Ok(password_entry)) = (
                    Entry::new("mpw", "default_user"),
                    Entry::new("mpw", "default_password"),
                ) {
                    if user_entry.set_password(&user).is_ok() && password_entry.set_password(&password).is_ok() {
                        println!("✓ Credentials updated in keyring.");
                    } else {
                        println!("⚠ Could not update credentials in keyring.");
                    }
                }
                
                // Update file storage
                if let Err(e) = save_file_credentials(&user, &password) {
                    println!("⚠ Could not save credentials to file: {}", e);
                } else {
                    println!("✓ Credentials saved to local file.");
                }
                
                println!("✓ Default credentials updated successfully.\n");
            }
            "2" => {
                println!("\n--- Current Credentials ---");
                if let Ok((user, _)) = load_file_credentials() {
                    println!("Username: {}", user);
                    println!("Password: [hidden]");
                    println!("Source: Local file");
                } else if let (Ok(user_entry), Ok(_)) = (
                    Entry::new("mpw", "default_user"),
                    Entry::new("mpw", "default_password"),
                ) {
                    if let Ok(user) = user_entry.get_password() {
                        println!("Username: {}", user);
                        println!("Password: [hidden]");
                        println!("Source: System keyring");
                    } else {
                        println!("No credentials found.");
                    }
                } else {
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
                    // Clear keyring (by overwriting with empty values)
                    if let (Ok(user_entry), Ok(password_entry)) = (
                        Entry::new("mpw", "default_user"),
                        Entry::new("mpw", "default_password"),
                    ) {
                        let _ = user_entry.set_password("");
                        let _ = password_entry.set_password("");
                        println!("✓ Cleared keyring credentials.");
                    }
                    
                    // Clear file
                    let creds_path = get_credentials_file_path();
                    if creds_path.exists() {
                        if let Err(e) = fs::remove_file(&creds_path) {
                            println!("⚠ Could not remove credentials file: {}", e);
                        } else {
                            println!("✓ Removed credentials file.");
                        }
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

fn get_or_store_credentials() -> Result<(String, String), Box<dyn std::error::Error>> {
    if let Ok((user, password)) = load_file_credentials() {
        return Ok((user, password));
    }

    if let (Ok(user_entry), Ok(password_entry)) = (
        Entry::new("mpw", "default_user"),
        Entry::new("mpw", "default_password"),
    ) {
        if let (Ok(user), Ok(password)) = (user_entry.get_password(), password_entry.get_password())
        {
            save_file_credentials(&user, &password).ok();
            return Ok((user, password));
        }
    }

    println!("No stored credentials found. Please set up default credentials:");
    print!("Default username: ");
    io::stdout().flush()?;
    let mut user = String::new();
    io::stdin().read_line(&mut user)?;
    let user = user.trim().to_string();

    let password = rpassword::prompt_password("Default master password: ")?;

    if let (Ok(user_entry), Ok(password_entry)) = (
        Entry::new("mpw", "default_user"),
        Entry::new("mpw", "default_password"),
    ) {
        if user_entry.set_password(&user).is_ok() && password_entry.set_password(&password).is_ok()
        {
            println!("Credentials stored securely in keyring.");
        } else {
            println!("Warning: Could not store credentials in keyring, using file storage.");
        }
    }

    if let Err(e) = save_file_credentials(&user, &password) {
        println!("Warning: Could not save credentials to file: {}", e);
    } else {
        println!("Credentials saved to local file.");
    }

    Ok((user, password))
}

fn main() {
    let args = Args::parse();

    // Handle setup mode
    if args.setup {
        match setup_credentials() {
            Ok(()) => {
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error in setup mode: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Handle regex search mode
    if let Some(regex_pattern) = args.regex {
        match search_entries_by_regex(&regex_pattern) {
            Ok(matching_sites) => {
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
            }
            Err(e) => {
                eprintln!("Error searching entries: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Regular password generation mode - site name is required
    let site_name = match args.site {
        Some(site) => site,
        None => {
            eprintln!(
                "Error: Site name is required for password generation. Use --site or --regex option."
            );
            std::process::exit(1);
        }
    };

    let (user, password) = match (args.user, args.password) {
        (Some(u), Some(p)) => (u, p),
        (user_arg, password_arg) => match get_or_store_credentials() {
            Ok((default_user, default_password)) => (
                user_arg.unwrap_or(default_user),
                password_arg.unwrap_or(default_password),
            ),
            Err(e) => {
                eprintln!("Error getting credentials: {}", e);
                std::process::exit(1);
            }
        },
    };

    let site_data = load_site_data(&site_name).unwrap_or_else(|e| {
        eprintln!("Warning: Could not load site data: {}", e);
        None
    });

    let counter = args
        .counter
        .unwrap_or_else(|| site_data.as_ref().map(|d| d.site_counter).unwrap_or(1));

    let template_str = args.template.unwrap_or_else(|| {
        site_data
            .as_ref()
            .map(|d| d.password_type.clone())
            .unwrap_or_else(|| "GeneratedLong".to_string())
    });

    let templates = if let Some(ref data) = site_data {
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
    };

    let master_pass = SecStr::from(password);
    let master_key = gen_master_key(master_pass.clone(), &user).unwrap();
    let site_seed = gen_site_seed(&master_key, &site_name, counter).unwrap();
    let password = gen_site_password(&site_seed, templates);
    let password_str = String::from_utf8_lossy(password.unsecure());

    // Enhanced workflow: handle username parsing, clipboard, and browser
    if let Some(ref data) = site_data {
        if let Some(ref user_name) = data.user_name {
            let (username, website, _comment) = parse_user_name(user_name);

            // Copy username to clipboard
            if let Err(e) = copy_to_clipboard(&username) {
                eprintln!("Warning: Could not copy username to clipboard: {}", e);
            } else {
                println!("✓ Username copied to clipboard: {}", username);
            }

            // Open website if it's a URL
            if let Some(ref url) = website {
                if url.starts_with("http") {
                    if let Err(e) = open_website(url) {
                        eprintln!("Warning: Could not open website: {}", e);
                    } else {
                        println!("✓ Opened website: {}", url);
                    }
                }
            }

            // Add a small delay to give time for clipboard operations
            std::thread::sleep(std::time::Duration::from_secs(1));

            // Copy password to clipboard
            if let Err(e) = copy_to_clipboard(&password_str) {
                eprintln!("Warning: Could not copy password to clipboard: {}", e);
            } else {
                println!("✓ Password copied to clipboard");
            }
        } else {
            // Fallback: just print password if no userName field
            println!("{}", password_str);
        }
    } else {
        // Fallback: just print password if no site data
        println!("{}", password_str);
    }

    let identicon = create_identicon(&master_pass, &user);
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

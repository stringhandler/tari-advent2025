use anyhow::anyhow;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, Key, XChaCha20Poly1305, XNonce};
use clap::{Parser, Subcommand};
use qrcode::QrCode;
use rusqlite::Connection;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Command;
use std::fs;
use tari_common::configuration::Network;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_common_types::types::{CompressedPublicKey, PrivateKey};
use tari_utilities::byte_array::ByteArray;

use crate::wallet_client::WalletClient;

mod wallet_client;

// Include encrypted days data at compile time
const ENCRYPTED_DAYS_CSV: &str = include_str!("./encrypted_days.csv");

#[derive(Deserialize)]
struct AddressData {
    view_key: String,
    spend_key: String,
}

#[derive(Parser)]
#[command(name = "tari-advent")]
#[command(about = "Tari Advent Calendar", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all 24 advent messages and their status
    List {
        /// Show detailed view with encrypted data
        #[arg(long)]
        long: bool,
    },
    /// Open a door for a specific day
    #[command(alias = "open-door")]
    Open {
        /// Day number (1-24)
        day: Option<u8>,
        /// Password to decrypt the message
        password: Option<String>,
        /// Path to minotari executable (default: minotari.exe)
        #[arg(short, long, default_value = "minotari.exe")]
        executable: String,
        /// Skip blockchain scanning
        #[arg(long)]
        no_scan: bool,
    },
    /// Generate addresses from CSV of passwords
    Generate {
        /// Path to CSV file containing 24 passwords
        csv_path: PathBuf,
        /// Output directory for generated files
        output_dir: PathBuf,
        /// Path to minotari executable (default: minotari.exe)
        #[arg(short, long)]
        executable: String,
        /// Column number to read passwords from (default: 0)
        #[arg(short, long, default_value = "0")]
        column: usize,
    },
    /// Show wallet information for a specific day
    Show {
        /// Day number (1-24)
        day: Option<u8>,
        /// Path to minotari executable (default: minotari.exe)
        #[arg(short, long, default_value = "minotari.exe")]
        executable: String,
        /// Skip blockchain scanning
        #[arg(long)]
        no_scan: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List { long } => list_messages(long),
        Commands::Open {
            day,
            password,
            executable,
            no_scan,
        } => {
            let client = wallet_client::BinaryWalletClient::new(executable.clone());

            open_door(day, password, client, no_scan).await
        }
        Commands::Generate {
            csv_path,
            output_dir,
            executable,
            column,
        } => generate_addresses(csv_path, output_dir, executable, column),
        Commands::Show { day, executable, no_scan } => {
            let client = wallet_client::BinaryWalletClient::new(executable.clone());
            show_day(day, client, no_scan).await
        }
    }
}

fn list_messages(long: bool) -> Result<(), anyhow::Error> {
    if long {
        // Detailed view with encrypted data
        println!("Tari Advent Calendar\n");

        // Parse encrypted data from CSV
        let encrypted_entries: Vec<&str> = ENCRYPTED_DAYS_CSV
            .lines()
            .skip(1) // Skip header
            .collect();

        for day in 1..=24 {
            let status = if is_unlocked(day) {
                "unlocked"
            } else {
                "locked"
            };

            println!("Day {}: {}", day, status);

            // Display encrypted data for this day
            if let Some(encrypted_data) = encrypted_entries.get(day as usize - 1) {
                println!("  Locked! Data: {}\n", encrypted_data);
            } else {
                println!("  Locked! Data: (no data available)\n");
            }
        }
    } else {
        // Grid view (6 columns x 4 rows)
        println!("Tari Advent Calendar\n");

        for row in 0..4 {
            for col in 0..6 {
                let day = row * 6 + col + 1;
                let is_unlocked_day = is_unlocked(day);

                let box_char = if is_unlocked_day { "📭" } else { "🔒" };
                print!(" {} {:2} ", box_char, day);
            }
            println!("\n");
        }
    }
    Ok(())
}

fn get_data_file_path() -> Option<PathBuf> {
    dirs::data_dir().map(|mut path| {
        path.push("tari-advent");
        fs::create_dir_all(&path).ok();
        path.push("unlocked.json");
        path
    })
}

fn get_wallet_dir() -> Result<PathBuf, anyhow::Error> {
    dirs::data_dir()
        .map(|mut path| {
            path.push("tari-advent");
            path.push("wallets");
            fs::create_dir_all(&path).ok();
            path
        })
        .ok_or_else(|| anyhow!("Could not get data directory"))
}

fn load_unlocked_days() -> HashMap<String, String> {
    let path = match get_data_file_path() {
        Some(p) => p,
        None => return HashMap::new(),
    };

    if !path.exists() {
        return HashMap::new();
    }

    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn save_unlocked_day(day: u8, password: &str) -> Result<(), String> {
    let path = get_data_file_path().ok_or("Could not get data directory")?;

    let mut unlocked = load_unlocked_days();
    unlocked.insert(format!("day{}", day), password.to_string());

    let json = serde_json::to_string_pretty(&unlocked)
        .map_err(|e| format!("JSON serialize error: {}", e))?;

    fs::write(&path, json).map_err(|e| format!("File write error: {}", e))?;

    Ok(())
}

fn is_unlocked(day: u8) -> bool {
    let unlocked = load_unlocked_days();
    unlocked.contains_key(&format!("day{}", day))
}

fn encrypt_keys(
    view_key: &str,
    spend_key: &str,
    password: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Derive a 32-byte key from the password using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();

    // Create cipher
    let key = Key::from(key_bytes);
    let cipher = XChaCha20Poly1305::new(&key);

    // Generate random nonce (12 bytes for ChaCha20Poly1305)
    let nonce_bytes = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Combine view_key and spend_key
    let combined = format!("{}|{}", view_key, spend_key);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, combined.as_bytes())
        .map_err(|e| format!("Encryption error: {}", e))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

fn decrypt_keys(encrypted_data: &str, password: &str) -> Result<(String, String), anyhow::Error> {
    // Decode base64
    let combined =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_data)
            .map_err(|e| anyhow!(format!("Base64 decode error: {}", e)))?;

    // XChaCha20Poly1305 uses 24-byte nonces
    if combined.len() < 24 {
        return Err(anyhow!("Invalid encrypted data: too short"));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(24);

    // Derive key from password
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();

    // Create cipher
    let key = Key::from(key_bytes);
    let cipher = XChaCha20Poly1305::new(&key);

    let nonce = XNonce::from_slice(nonce_bytes);

    // Decrypt
    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!(format!("Decryption error: {}", e)))?;

    // Convert to string and split
    let decrypted_str =
        String::from_utf8(decrypted).map_err(|e| anyhow!(format!("UTF-8 decode error: {}", e)))?;

    let parts: Vec<&str> = decrypted_str.split('|').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid decrypted data format"));
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

async fn open_door<T: WalletClient>(
    day: Option<u8>,
    password: Option<String>,
    client: T,
    no_scan: bool,
) -> Result<(), anyhow::Error> {
    // Prompt for day if not provided
    let day = match day {
        Some(d) => d,
        None => {
            print!("Enter day number (1-24): ");
            io::stdout().flush().unwrap();
            let stdin = io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line).unwrap();
            line.trim().parse::<u8>()?
        }
    };

    if !(1..=24).contains(&day) {
        eprintln!("Error: Day must be between 1 and 24");
        return Err(anyhow!("Day must be between 1 and 24"));
    }

    // Prompt for password if not provided
    let password = match password {
        Some(p) => p,
        None => {
            print!("Enter password: ");
            io::stdout().flush().unwrap();
            let stdin = io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line).unwrap();
            line.trim().to_string()
        }
    };

    // Parse encrypted data from CSV
    let encrypted_entries: Vec<&str> = ENCRYPTED_DAYS_CSV
        .lines()
        .skip(1) // Skip header
        .collect();

    // Get encrypted data for the specific day
    let encrypted_data = encrypted_entries
        .get(day as usize - 1)
        .ok_or_else(|| anyhow!("Could not get encrypted day"))?;

    // Try to decrypt
    match decrypt_keys(encrypted_data, &password) {
        Ok((view_key, spend_key)) => {
            // Save the successful password
            if let Err(e) = save_unlocked_day(day, &password) {
                eprintln!("Warning: Could not save unlock state: {}", e);
            }

            println!("\n🎉 Congrats! 🎉\n");
            println!("Day {} unlocked!", day);
            println!("View Key:  {}", view_key);
            println!("Spend Key: {}", spend_key);

            // Get wallet directory
            let wallet_dir = get_wallet_dir()?;

            let wallet_file = wallet_dir.join(format!("wallet-day-{}.sqlite", day));

            // Only import if the database doesn't exist
            if !wallet_file.exists() {
                println!("\n📂 Importing keys for day {}...", day);

                client
                    .import_view_key(&view_key, &spend_key, "password1", &wallet_file)
                    .await?;
                // let import_status = Command::new(&executable)
                //     .arg("import-view-key")
                //     .arg("-v")
                //     .arg(&view_key)
                //     .arg("-s")
                //     .arg(&spend_key)
                //     .arg("-p")
                //     .arg("password1")
                //     .arg("-b")
                //     .arg("1435")
                //     .arg("-d")
                //     .arg(&wallet_file)
                //     .stdout(Stdio::null())
                //     .stderr(Stdio::null())
                //     .status();
            } else {
                println!("\n📂 Wallet database already exists for day {}", day);
            }

            if !no_scan {
                println!("🔍 Scanning wallet...");

                // Scan wallet
                client
                    .scan(&wallet_file, "password1", "https://rpc.tari.com")
                    .await?;
            } else {
                println!("⏭️  Skipping wallet scan");
            }
            // Construct TariAddress from the keys
            match construct_tari_address(&view_key, &spend_key) {
                Ok(address) => {
                    let display_address = address.to_base58();
                    println!(
                        "\n==========================================================================================="
                    );
                    println!(
                        "\n To show you found it, send a tiny amount of tari (e.g. 0.000001 XTM) WITH A MESSAGE to:"
                    );
                    println!("\n🏦 Wallet Address: {}", display_address);

                    // Generate and display QR code
                    match QrCode::new(&display_address) {
                        Ok(qr) => {
                            println!("\n📱 QR Code:\n");
                            let qr_string = qr
                                .render::<char>()
                                .quiet_zone(false)
                                .module_dimensions(2, 1)
                                .build();
                            println!("{}", qr_string);
                        }
                        Err(e) => {
                            eprintln!("⚠️  Warning: Could not generate QR code: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Warning: Could not construct Tari address: {}", e);
                }
            }

            // Query the outputs table for messages
            println!("\n📬 Messages:");
            match Connection::open(&wallet_file) {
                Ok(conn) => {
                    match conn.prepare(
                        "SELECT mined_timestamp, memo_parsed FROM outputs WHERE memo_parsed IS NOT NULL AND memo_parsed != '' ORDER BY mined_timestamp"
                    ) {
                        Ok(mut stmt) => {
                            match stmt.query_map([], |row| {
                                Ok((
                                    row.get::<_, String>(0)?,
                                    row.get::<_, String>(1)?,
                                ))
                            }) {
                                Ok(messages) => {
                                    let mut found_any = false;
                                    for message in messages {
                                        match message {
                                            Ok((timestamp, memo)) => {
                                                found_any = true;
                                                println!("   [{}] {}", timestamp, memo);
                                            }
                                            Err(e) => {
                                                eprintln!("⚠️  Error reading message: {}", e);
                                            }
                                        }
                                    }
                                    if !found_any {
                                        println!("   (No messages found)\n");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("⚠️  Could not query messages: {}", e);
                                    println!("   (No messages found or database error)\n");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("⚠️  Could not prepare query: {}", e);
                            println!("   (No messages found or database error)\n");
                        }
                    }
                    conn.close().ok();
                }
                Err(e) => {
                    eprintln!("⚠️  Could not open database: {}", e);
                    println!("   (No messages found or database error)\n");
                }
            }

            println!("\n✅ Wallet for day {} is ready!", day);
        }
        Err(e) => {
            eprintln!("❌ Failed to open door: {}", e);
            eprintln!("The password may be incorrect.");
        }
    }

    Ok(())
}

async fn show_day<T: WalletClient>(day: Option<u8>, client: T, no_scan: bool) -> Result<(), anyhow::Error> {
    // Prompt for day if not provided
    let day = match day {
        Some(d) => d,
        None => {
            print!("Enter day number (1-24): ");
            io::stdout().flush().unwrap();
            let stdin = io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line).unwrap();
            line.trim().parse::<u8>()?
        }
    };

    if !(1..=24).contains(&day) {
        eprintln!("Error: Day must be between 1 and 24");
        return Err(anyhow!("Day must be between 1 and 24"));
    }

    // Check if day is unlocked
    if !is_unlocked(day) {
        println!("🔒 Locked, you need a password to open it");
        return Err(anyhow!("Day {} is locked", day));
    }

    // Get the saved password
    let unlocked = load_unlocked_days();
    let password = unlocked
        .get(&format!("day{}", day))
        .ok_or_else(|| anyhow!("Could not find day in unlock"))?;

    // Get encrypted data and decrypt to get keys
    let encrypted_entries: Vec<&str> = ENCRYPTED_DAYS_CSV.lines().skip(1).collect();

    let encrypted_data = encrypted_entries
        .get(day as usize - 1)
        .ok_or_else(|| anyhow!("Error: No encrypted data found for day"))?;

    let (view_key, spend_key) = decrypt_keys(encrypted_data, password)?;

    // Get wallet directory
    let wallet_dir = get_wallet_dir()?;

    let wallet_file = wallet_dir.join(format!("wallet-day-{}.sqlite", day));

    // Only import if the database doesn't exist
    if !wallet_file.exists() {
        println!("📂 Importing keys for day {}...", day);

        // Import view key
        client
            .import_view_key(&view_key, &spend_key, password, &wallet_file)
            .await?;
    }

    if !no_scan {
        println!("🔍 Scanning wallet...");

        // Scan wallet
        client
            .scan(&wallet_file, "password1", "https://rpc.tari.com")
            .await?;
    } else {
        println!("⏭️  Skipping wallet scan");
    }

    // Construct TariAddress from the keys
    match construct_tari_address(&view_key, &spend_key) {
        Ok(address) => {
            let display_address = address.to_base58();
            println!(
                "==========================================================================================="
            );
            println!(
                "\n To show you found it, send a tiny amount of tari (e.g. 0.000001 XTM) WITH A MESSAGE to:"
            );
            println!("\n🏦 Wallet Address: {}", display_address);

            // Generate and display QR code
            match QrCode::new(&display_address) {
                Ok(qr) => {
                    println!("\n📱 QR Code:\n");
                    let qr_string = qr
                        .render::<char>()
                        .quiet_zone(false)
                        .module_dimensions(2, 1)
                        .build();
                    println!("{}", qr_string);
                }
                Err(e) => {
                    eprintln!("⚠️  Warning: Could not generate QR code: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("⚠️  Warning: Could not construct Tari address: {}", e);
        }
    }

    // Query the outputs table for messages
    println!("\n📬 Messages:");
    match Connection::open(&wallet_file) {
        Ok(conn) => {
            match conn.prepare(
                "SELECT mined_timestamp, memo_parsed FROM outputs WHERE memo_parsed IS NOT NULL AND memo_parsed != '' ORDER BY mined_timestamp"
            ) {
                Ok(mut stmt) => {
                    match stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                        ))
                    }) {
                        Ok(messages) => {
                            let mut found_any = false;
                            for message in messages {
                                match message {
                                    Ok((timestamp, memo)) => {
                                        found_any = true;
                                        println!("   [{}] {}", timestamp, memo);
                                    }
                                    Err(e) => {
                                        eprintln!("⚠️  Error reading message: {}", e);
                                    }
                                }
                            }
                            if !found_any {
                                println!("   (No messages found)\n");
                            }
                        }
                        Err(e) => {
                            eprintln!("⚠️  Could not query messages: {}", e);
                            println!("   (No messages found or database error)\n");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Could not prepare query: {}", e);
                    println!("   (No messages found or database error)\n");
                }
            }
            conn.close().ok();
        }
        Err(e) => {
            eprintln!("⚠️  Could not open database: {}", e);
            println!("   (No messages found or database error)\n");
        }
    }

    println!("\n✅ Wallet for day {} is ready!", day);
    Ok(())
}

fn construct_tari_address(
    view_key_hex: &str,
    spend_key_hex: &str,
) -> Result<TariAddress, anyhow::Error> {
    // Parse view key from hex
    let view_key_bytes = hex::decode(view_key_hex)?;

    let view_key = PrivateKey::from_canonical_bytes(&view_key_bytes).map_err(anyhow::Error::msg)?;

    let pub_view_key = CompressedPublicKey::from_secret_key(&view_key);
    // Parse spend key from hex
    let spend_key_bytes = hex::decode(spend_key_hex)?;

    let spend_key =
        CompressedPublicKey::from_canonical_bytes(&spend_key_bytes).map_err(anyhow::Error::msg)?;

    // Construct TariAddress
    let address = TariAddress::new_dual_address(
        pub_view_key,
        spend_key,
        Network::MainNet,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )?;

    Ok(address)
}

fn generate_addresses(
    csv_path: PathBuf,
    output_dir: PathBuf,
    executable: String,
    column: usize,
) -> Result<(), anyhow::Error> {
    // Read the CSV file
    let csv_content = match fs::read_to_string(&csv_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading CSV file: {}", e);
            return Err(anyhow::Error::new(e));
        }
    };

    // Parse passwords from CSV, extracting the specified column
    let passwords: Vec<String> = csv_content
        .lines()
        .filter_map(|line| {
            let columns: Vec<&str> = line.split(',').collect();
            columns.get(column).map(|s| s.trim().to_string())
        })
        .collect();

    if passwords.len() != 24 {
        eprintln!(
            "Error: CSV file must contain exactly 24 rows with data in column {}, found {}",
            column,
            passwords.len()
        );
        return Err(anyhow::Error::msg("Invalid number of passwords in CSV"));
    }

    // Create output directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&output_dir) {
        eprintln!("Error creating output directory: {}", e);
        return Err(anyhow::Error::new(e));
    }

    // Array to store all address data (password, view_key, spend_key)
    let mut all_addresses: Vec<(String, String, String)> = Vec::new();
    // Array to store encrypted data with passwords
    let mut encrypted_data: Vec<(String, String)> = Vec::new();

    // Generate addresses for each day
    for (index, password) in passwords.iter().enumerate() {
        let day = index + 1;
        let output_file = output_dir.join(format!("day-{}.json", day));

        println!(
            "Generating address for day {} with password: {}",
            day, password
        );

        let status = Command::new(&executable)
            .arg("create-address")
            .arg("-o")
            .arg(&output_file)
            .status();

        match status {
            Ok(exit_status) => {
                if exit_status.success() {
                    println!("✓ Day {} completed: {:?}", day, output_file);

                    // Read the generated JSON file
                    match fs::read_to_string(&output_file) {
                        Ok(json_content) => {
                            match serde_json::from_str::<AddressData>(&json_content) {
                                Ok(address_data) => {
                                    all_addresses.push((
                                        password.to_string(),
                                        address_data.view_key.clone(),
                                        address_data.spend_key.clone(),
                                    ));

                                    // Encrypt the keys with the password
                                    match encrypt_keys(
                                        &address_data.view_key,
                                        &address_data.spend_key,
                                        password,
                                    ) {
                                        Ok((nonce, ciphertext)) => {
                                            // Combine nonce and ciphertext, then encode as base64
                                            let mut combined = nonce;
                                            combined.extend_from_slice(&ciphertext);
                                            let encoded = base64::Engine::encode(
                                                &base64::engine::general_purpose::STANDARD,
                                                &combined,
                                            );
                                            encrypted_data.push((password.to_string(), encoded));
                                        }
                                        Err(e) => {
                                            eprintln!("✗ Day {} encryption error: {}", day, e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("✗ Day {} error parsing JSON: {}", day, e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("✗ Day {} error reading generated file: {}", day, e);
                        }
                    }
                } else {
                    eprintln!("✗ Day {} failed with status: {}", day, exit_status);
                }
            }
            Err(e) => {
                eprintln!("✗ Day {} error executing {}: {}", day, executable, e);
            }
        }
    }

    // Write all addresses to all.csv
    let csv_output_path = output_dir.join("all.csv");
    match fs::File::create(&csv_output_path) {
        Ok(mut file) => {
            // Write CSV header
            if let Err(e) = writeln!(file, "password,view_key,spend_key") {
                eprintln!("Error writing CSV header: {}", e);
                return Err(anyhow::Error::new(e));
            }

            // Write each address
            for (password, view_key, spend_key) in all_addresses {
                if let Err(e) = writeln!(file, "{},{},{}", password, view_key, spend_key) {
                    eprintln!("Error writing CSV row: {}", e);
                    return Err(anyhow::Error::new(e));
                }
            }

            println!("\n✓ All addresses written to: {:?}", csv_output_path);
        }
        Err(e) => {
            eprintln!("Error creating all.csv: {}", e);
        }
    }

    // Write encrypted data to encrypted_days.csv
    let encrypted_days_output_path = output_dir.join("encrypted_days.csv");
    match fs::File::create(&encrypted_days_output_path) {
        Ok(mut file) => {
            // Write CSV header
            if let Err(e) = writeln!(file, "encrypted_data") {
                eprintln!("Error writing passwords.csv header: {}", e);
                return Err(anyhow::Error::new(e));
            }

            // Write each encrypted entry
            for (_password, encrypted) in encrypted_data {
                if let Err(e) = writeln!(file, "{}", encrypted) {
                    eprintln!("Error writing passwords.csv row: {}", e);
                    return Err(anyhow::Error::new(e));
                }
            }

            println!(
                "✓ Encrypted data written to: {:?}",
                encrypted_days_output_path
            );
        }
        Err(e) => {
            eprintln!("Error creating encrypted_days.csv: {}", e);
        }
    }

    println!("\nGeneration complete!");
    Ok(())
}

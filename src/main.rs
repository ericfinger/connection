use std::fs::{read_dir, remove_file};

use anyhow::{Context, Result, anyhow, bail};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
};
use clap::Parser;
use confy::{get_configuration_file_path, load, store};
use inquire::{Confirm, CustomType, Password, Select, Text, validator::ValueRequiredValidator};
use serde::{Deserialize, Serialize};

mod connection;
#[allow(unused_imports)]
use crate::connection::Connection;

#[derive(Default, Parser, Serialize, Deserialize, Debug)]
#[command(version, about, long_about = "A modern Port-Knocking Client")]
struct Cli {
    /// The host/IP to send the knock to OR the name of a preset
    #[arg(value_names = ["host | preset"], required_unless_present_any = ["new", "list", "delete", "delete_all"])]
    host: Option<String>,

    /// The Sequence of ports, seperated by spaces. Example: 1234 5678:udp 9101:tcp
    #[arg(value_names = ["port<:proto>"])]
    ports: Vec<String>,

    /// Make all ports hits use UDP (default is TCP)
    #[arg(short, long)]
    udp: bool,

    /// Wait <t> milliseconds between Port hits
    #[arg(short, long, value_names = ["t"], default_value_t = 0)]
    delay: u64,

    /// Force usage of IPv4
    #[arg(short = '4', long, name = "4", conflicts_with("6"))]
    ipv4: bool,

    /// Force usage of IPv6
    #[arg(short = '6', long, name = "6", conflicts_with("4"))]
    ipv6: bool,

    /// Be verbose
    #[arg(short, long)]
    verbose: bool,

    /// Run a command after the knock
    #[arg(short, long, value_names = ["cmd"])]
    command: Option<String>,

    /// Don't run a command after the knock, even if configured in preset
    #[arg(short, long)]
    #[serde(skip_deserializing, skip_serializing)]
    no_command: bool,

    /// List all presets
    #[arg(short, long, help_heading = Some("Presets"), exclusive = true)]
    #[serde(skip_deserializing, skip_serializing)]
    list: bool,

    /// Run the Wizard to create a new preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"), exclusive = true)]
    #[serde(skip_deserializing, skip_serializing)]
    new: Option<String>,

    /// Run the wizard to change a preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"), exclusive = true)]
    #[serde(skip_deserializing, skip_serializing)]
    reconfigure: Option<String>,

    /// Delete a preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"), exclusive = true)]
    #[serde(skip_deserializing, skip_serializing)]
    delete: Option<String>,

    /// Delete all presets
    #[arg(long, help_heading = Some("Presets"), exclusive = true)]
    #[serde(skip_deserializing, skip_serializing)]
    delete_all: bool,

    #[clap(skip)]
    salt: Option<String>,

    #[clap(skip)]
    nonce: Option<Vec<u8>>,

    #[clap(skip)]
    encrypted_content: Option<Vec<u8>>,
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    if let Some(name) = &cli.new {
        create_config(name)?;
        println!(
            "New config successfully created. Try it now with 'connection {}'",
            name
        );
        return Ok(());
    }

    if let Some(name) = &cli.reconfigure {
        if get_configuration_file_path("connection", Some(name.as_ref()))?.exists() {
            create_config(name)?;
            println!(
                "Config '{name}' successfully reconfigured. Try it now with 'connection {name}'"
            );
        } else {
            bail!("Config '{name}' was not found");
        }
        return Ok(());
    }

    if let Some(name) = &cli.delete {
        let path = get_configuration_file_path("connection", Some(name.as_ref()))?;
        if path.exists() {
            remove_file(&path).context(format!("Could not delete {:?}", path))?;
            println!("Config '{name}' successfully deleted.");
        } else {
            bail!("Config '{name}' was not found");
        }

        return Ok(());
    }

    if cli.delete_all {
        if !Confirm::new("Are you sure you want to DELETE all Presets?")
            .with_default(false)
            .prompt()?
        {
            return Ok(());
        }
        let path = get_configuration_file_path("connection", None)?;
        let path = path
            .parent()
            .context(format!("Could not get parent directory of file {:?}", path))?;

        if !path.exists() {
            bail!("No Presets found");
        }

        let files =
            read_dir(path).context(format!("Could not read directory content in {:?}", path))?;
        for file in files {
            let file_path = file?.path();
            remove_file(&file_path).context(format!("Could not delete file {:?}", file_path))?;
        }
        println!("Successfully Deleted all Presets");

        return Ok(());
    }

    if cli.list {
        let path = get_configuration_file_path("connection", None)?;
        let path = path
            .parent()
            .context(format!("Could not get parent directory of file {:?}", path))?;

        if !path.exists() {
            bail!("No Presets found");
        }

        let files =
            read_dir(path).context(format!("Could not read directory entries in {:?}", path))?;

        for file in files {
            let filename = file?.file_name();
            println!(
                "- {}",
                filename
                    .to_str()
                    .context(format!(
                        "Could not convert filename {:?} to string",
                        filename
                    ))?
                    .replace(".toml", "")
            );
        }

        return Ok(());
    }

    // if a preset exists load it:
    if get_configuration_file_path("connection", Some(cli.host.as_ref().unwrap().as_ref()))?
        .exists()
    {
        if cli.verbose {
            println!(
                "Preset '{}' found, loading settings",
                cli.host.as_ref().unwrap()
            );
        }

        let mut cli_loaded: Cli = load("connection", Some(cli.host.as_ref().unwrap().as_ref()))
            .context(format!(
                "Could not load config file for '{}'",
                cli.host.as_ref().unwrap()
            ))?;

        if let Some(encrypted_content) = cli_loaded.encrypted_content {
            let password = Password::new(&format!(
                "Enter the password for config file '{}'",
                cli.host.as_ref().unwrap()
            ))
            .with_validator(ValueRequiredValidator::default())
            .without_confirmation()
            .prompt()?;

            let Some(salt) = cli_loaded.salt else {
                if let Err(e) =
                    migrate_encrypted_config(password, &encrypted_content, cli.host.unwrap())
                {
                    bail!(
                        "Could not read salt from encrypted config file: {}",
                        e.to_string()
                    );
                } else {
                    return Ok(());
                }
            };

            let Some(nonce) = cli_loaded.nonce else {
                bail!("Could not read nonce from encrypted config file!");
            };

            assert!(nonce.len() == 12);
            let nonce: [u8; 12] = nonce.try_into().unwrap();

            let salt = SaltString::from_b64(&salt)
                .map_err(|e| anyhow!("Failed to parse salt: {}", e.to_string()))?;

            let key = derive_key(password, &salt)?;

            cli_loaded = decrypt_config(&encrypted_content, key, nonce)?;
        };

        // Prioritize CLI switches over config file:
        cli_loaded.verbose |= cli.verbose;
        cli_loaded.no_command |= cli.no_command;
        cli_loaded.udp |= cli.udp;

        if cli.ipv4 {
            cli_loaded.ipv4 = true;
            cli_loaded.ipv6 = false;
        }

        if cli.ipv6 {
            cli_loaded.ipv6 = true;
            cli_loaded.ipv4 = false;
        }

        // Prioritize CLI options over config file:
        cli_loaded.delay = cli.delay.max(cli_loaded.delay);

        if cli.command.is_some() {
            cli_loaded.no_command = false;
            cli_loaded.command = cli.command.clone();
        }

        cli = cli_loaded;
    }

    let connection = Connection::new(cli)?;
    connection.execute_knock()?;
    connection.exec_cmd()?;

    Ok(())
}

fn create_config(name: &str) -> Result<()> {
    let host = Text::new("Host:")
        .with_validator(ValueRequiredValidator::default())
        .prompt()?;

    let host = Some(host);

    let udp = Confirm::new("Use UDP as default instead of TCP?")
        .with_default(false)
        .prompt()?;

    let ports_str = Text::new("Ports:")
        .with_help_message("Space seperated list of Ports to knock on, the protocol can optionally be specified with :tcp or :udp per Port")
        .with_placeholder("1234 5678:udp 9101:tcp")
        .with_validator(ValueRequiredValidator::default())
    .prompt()?;

    let mut ports = Vec::new();
    for port in ports_str.trim().split(' ') {
        ports.push(port.to_string());
    }

    let delay = CustomType::new("Delay:")
        .with_help_message("Delay between Port-hits in milliseconds")
        .with_default(100)
        .prompt()?;

    let ipv_options = vec!["Don't care", "IPv4", "IPv6"];
    let ipv = Select::new("Select the IP Version", ipv_options).prompt()?;

    let mut ipv4 = false;
    let mut ipv6 = false;
    match ipv {
        "IPv4" => ipv4 = true,
        "IPv6" => ipv6 = true,
        _ => {}
    }

    let verbose = Confirm::new("Do you want connection to be verbose?")
        .with_default(false)
        .prompt()?;

    let mut command = None;
    let cmd = Text::new("Command to run after knocking:")
        .with_help_message("Leave Empty for none")
        .with_placeholder("ssh -p 2222 user@server.com")
        .prompt()?;

    if !cmd.is_empty() {
        command = Some(cmd);
    }

    let encrypted = Confirm::new("Do you want to password-protect the config?")
        .with_default(true)
        .prompt()?;

    let cli = Cli {
        host,
        ports,
        udp,
        delay,
        ipv4,
        ipv6,
        verbose,
        command,
        no_command: false,
        list: false,
        new: None,
        reconfigure: None,
        delete: None,
        delete_all: false,
        salt: None,
        nonce: None,
        encrypted_content: None,
    };

    if encrypted {
        let password = Password::new("Enter your password:")
            .with_validator(ValueRequiredValidator::default())
            .prompt()?;

        // let crypt = new_magic_crypt!(key, 256);
        // let json = serde_json::to_string(&cli)?;
        // let encrypted_content = crypt.encrypt_str_to_bytes(json);
        let salt = SaltString::generate(&mut OsRng);
        let key_bytes = derive_key(password, &salt)?;
        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let encrypted_content = create_encrypted_config(&cli, key_bytes, nonce_bytes)?;

        let cli_encrypted = Cli {
            host: None,
            ports: Vec::new(),
            udp: false,
            delay: 0,
            ipv4: false,
            ipv6: false,
            verbose: false,
            command: None,
            no_command: false,
            list: false,
            new: None,
            reconfigure: None,
            delete: None,
            delete_all: false,
            salt: Some(salt.to_string()),
            nonce: Some(nonce_bytes.to_vec()),
            encrypted_content: Some(encrypted_content),
        };
        store("connection", name, cli_encrypted).context("Could not store config")?;
        return Ok(());
    }

    store("connection", name, cli).context("Could not store config")?;

    Ok(())
}

fn derive_key(password: String, salt: &SaltString) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| anyhow!("{}", e.to_string()))
        .context("Could not hash password")?;

    let hash_bytes = password_hash
        .hash
        .expect("Could not get hash-bytes from password hash");

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
    Ok(key)
}

fn create_encrypted_config(cli: &Cli, key: [u8; 32], nonce: [u8; 12]) -> Result<Vec<u8>> {
    let key = GenericArray::clone_from_slice(&key);
    let nonce = Nonce::from_slice(&nonce);
    let cipher = ChaCha20Poly1305::new(&key);
    let encoded_struct = bincode::serde::encode_to_vec(cli, bincode::config::standard())?;

    let encrypted_data = cipher
        .encrypt(nonce, encoded_struct.as_ref())
        .map_err(|e| anyhow!("Failed to encrypt data: {}", e.to_string()))
        .context("Encryption failed")?;

    Ok(encrypted_data)
}

fn decrypt_config(encrypted_content: &[u8], key: [u8; 32], nonce: [u8; 12]) -> Result<Cli> {
    let key = GenericArray::clone_from_slice(&key);
    let cipher = ChaCha20Poly1305::new(&key);

    let cli_encoded = cipher
        .decrypt(Nonce::from_slice(&nonce), encrypted_content)
        .map_err(|e| anyhow!("Could not decrypt config file: {}", e.to_string()))?;

    let cli: Cli = bincode::serde::decode_from_slice(&cli_encoded, bincode::config::standard())?.0;

    Ok(cli)
}

use magic_crypt::{MagicCryptTrait, new_magic_crypt};

/// Migrates an old json+magic_crypt based config to the new bincode+chacha20poly1305 format
fn migrate_encrypted_config(
    password: String,
    encrypted_content: &[u8],
    config_name: String,
) -> Result<()> {
    let migrate = Confirm::new("Your config needs to be migrated. Perform the migration now?")
        .with_default(true)
        .prompt()?;

    if !migrate {
        println!("Migration denied, quitting.");
        std::process::exit(0);
    }

    let crypt = new_magic_crypt!(password.clone(), 256);
    let decrypted_content = crypt
        .decrypt_bytes_to_bytes(&encrypted_content)
        .context("Could not decrypt config. Wrong Password?")?;
    let cli: Cli = serde_json::from_str(
        &String::from_utf8(decrypted_content).expect("Could not decode encrypted config as json"),
    )?;

    let salt = SaltString::generate(&mut OsRng);
    let key_bytes = derive_key(password, &salt)?;

    // Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let encrypted_content = create_encrypted_config(&cli, key_bytes, nonce_bytes)?;

    let cli_encrypted = Cli {
        host: None,
        ports: Vec::new(),
        udp: false,
        delay: 0,
        ipv4: false,
        ipv6: false,
        verbose: false,
        command: None,
        no_command: false,
        list: false,
        new: None,
        reconfigure: None,
        delete: None,
        delete_all: false,
        salt: Some(salt.to_string()),
        nonce: Some(nonce_bytes.to_vec()),
        encrypted_content: Some(encrypted_content),
    };

    store("connection", config_name.as_ref(), &cli_encrypted).context("Could not store config")?;

    println!(
        "Successfully migrated config '{}'. You can use it now with 'connection {}'",
        config_name, config_name
    );

    Ok(())
}

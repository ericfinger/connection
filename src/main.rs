use std::fs::{read_dir, remove_file};

use anyhow::{bail, Context, Result};
use clap::Parser;
use confy::{get_configuration_file_path, load, store};
use inquire::{validator::ValueRequiredValidator, Confirm, CustomType, Password, Select, Text};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
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
    #[arg(short, long, requires = "host")]
    udp: bool,

    /// Wait <t> milliseconds between Port hits
    #[arg(short, long, value_names = ["t"], default_value_t = 0, requires = "host")]
    delay: u64,

    /// Force usage of IPv4
    #[arg(short = '4', long, requires = "host")]
    ipv4: bool,

    /// Force usage of IPv6
    #[arg(short = '6', long, requires = "host")]
    ipv6: bool,

    /// Be verbose
    #[arg(short, long, requires = "host")]
    verbose: bool,

    /// Run a command after the knock
    #[arg(short, long, value_names = ["cmd"], requires = "host")]
    command: Option<String>,

    /// List all presets
    #[arg(short, long, help_heading = Some("Presets"), exclusive = true)]
    list: bool,

    /// Run the Wizard to create a new preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"), exclusive = true)]
    new: Option<String>,

    /// Run the wizard to change a preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"), exclusive = true)]
    reconfigure: Option<String>,

    /// Delete a preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"), exclusive = true)]
    delete: Option<String>,

    /// Delete all presets
    #[arg(long, help_heading = Some("Presets"), exclusive = true)]
    delete_all: bool,

    #[clap(skip)]
    encrypted: bool,
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

        let cli_loaded: Cli = load("connection", Some(cli.host.as_ref().unwrap().as_ref()))
            .context(format!(
                "Could not load config file for '{}'",
                cli.host.as_ref().unwrap()
            ))?;

        if cli_loaded.encrypted {
            let key = Password::new(&format!(
                "Enter the password for config file {}",
                cli.host.as_ref().unwrap()
            ))
            .with_validator(ValueRequiredValidator::default())
            .without_confirmation()
            .prompt()?;

            let crypt = new_magic_crypt!(key, 256);
            let decrypted_content =
                crypt.decrypt_bytes_to_bytes(&cli_loaded.encrypted_content.clone().unwrap())?;
            cli = serde_json::from_str(
                &String::from_utf8(decrypted_content)
                    .expect("Could not decode encrypted config as json"),
            )?;
        }
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
    for port in ports_str.split(' ') {
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
        list: false,
        new: None,
        reconfigure: None,
        delete: None,
        delete_all: false,
        encrypted,
        encrypted_content: None,
    };

    if encrypted {
        let key = Password::new("Enter your password:")
            .with_validator(ValueRequiredValidator::default())
            .prompt()?;

        let crypt = new_magic_crypt!(key, 256);
        let json = serde_json::to_string(&cli)?;
        let encrypted_content = crypt.encrypt_str_to_bytes(json);

        let cli_encrypted = Cli {
            host: None,
            ports: Vec::new(),
            udp: false,
            delay: 0,
            ipv4: false,
            ipv6: false,
            verbose: false,
            command: None,
            list: false,
            new: None,
            reconfigure: None,
            delete: None,
            delete_all: false,
            encrypted: true,
            encrypted_content: Some(encrypted_content),
        };
        store("connection", name, cli_encrypted).context("Could not store config")?;
        return Ok(());
    }

    store("connection", name, cli).context("Could not store config")?;

    Ok(())
}

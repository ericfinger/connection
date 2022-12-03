use std::fs::{read_dir, remove_file};

use clap::Parser;
use confy::{get_configuration_file_path, load, store};
use inquire::{validator::ValueRequiredValidator, Confirm, CustomType, Select, Text};
use serde::{Deserialize, Serialize};

mod connection;
#[allow(unused_imports)]
use crate::connection::Connection;

#[derive(Default, Parser, Serialize, Deserialize)]
#[command(version, about, long_about = "A modern Port-Knocking Client")]
struct Cli {
    /// The host/IP to send the knock to OR the name of a preset
    #[arg(value_names = ["host | preset"])]
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
}

fn main() {
    let mut cli = Cli::parse();

    if let Some(name) = &cli.new {
        create_config(name);
        println!(
            "New config successfully created. Try it now with 'connection {}'",
            name
        );
        return;
    }

    if let Some(name) = &cli.reconfigure {
        if get_configuration_file_path("connection", Some(name.as_ref()))
            .unwrap()
            .exists()
        {
            create_config(name);
            println!(
                "Config '{}' successfully reconfigured. Try it now with 'connection {}'",
                name, name
            );
        } else {
            eprintln!("Config '{}' was not found.", name);
        }
        return;
    }

    if let Some(name) = &cli.delete {
        if let Ok(path) = get_configuration_file_path("connection", Some(name.as_ref())) {
            if path.exists() {
                remove_file(path).unwrap();
                println!("Config '{}' successfully deleted.", name);
            } else {
                eprintln!("Config '{}' was not found.", name);
            }
        }
        return;
    }

    if cli.delete_all {
        if !Confirm::new("Are you sure you want to DELETE all Presets?")
            .with_default(false)
            .prompt()
            .unwrap()
        {
            return;
        }
        let path = get_configuration_file_path("connection", None).unwrap();
        let path = path.parent().unwrap();

        if path.exists() {
            let files = read_dir(path).unwrap();

            for file in files {
                remove_file(file.unwrap().path()).unwrap();
            }

            println!("Successfully Deleted all Presets");
        } else {
            println!("No presets found");
        }
        return;
    }

    if cli.list {
        let path = get_configuration_file_path("connection", None).unwrap();
        let path = path.parent().unwrap();

        if path.exists() {
            let files = read_dir(path).unwrap();

            for file in files {
                println!(
                    "- {}",
                    file.unwrap()
                        .file_name()
                        .to_str()
                        .unwrap()
                        .replace(".toml", "")
                );
            }
        } else {
            println!("No presets found.");
        }
        return;
    }

    // if a preset exists load it:
    if get_configuration_file_path("connection", Some(cli.host.as_ref().unwrap().as_ref()))
        .unwrap()
        .exists()
    {
        if cli.verbose {
            println!(
                "Preset '{}' found, loading settings",
                cli.host.as_ref().unwrap()
            );
        }
        cli = load("connection", Some(cli.host.unwrap().as_ref())).unwrap();
    }

    let connection = Connection::new(cli);
    connection.execute_knock();
    connection.exec_cmd();
}

fn create_config(name: &str) {
    let host = Some(
        Text::new("Host:")
            .with_validator(ValueRequiredValidator::default())
            .prompt()
            .unwrap(),
    );

    let udp = Confirm::new("Use UDP as default instead of TCP?")
        .with_default(false)
        .prompt()
        .unwrap();

    let ports_str = Text::new("Ports:")
        .with_help_message("Space seperated list of Ports to knock on, the protocol can optionally be specified with :tcp or :udp per Port")
        .with_placeholder("1234 5678:udp 9101:tcp")
        .with_validator(ValueRequiredValidator::default())
        .prompt()
        .unwrap();

    let mut ports = Vec::new();
    for port in ports_str.split(' ') {
        ports.push(port.to_string());
    }

    let delay = CustomType::new("Delay:")
        .with_help_message("Delay between Port-hits in milliseconds")
        .with_default(100)
        .prompt()
        .unwrap();

    let ipv_options = vec!["Don't care", "IPv4", "IPv6"];
    let ipv = Select::new("Select the IP Version", ipv_options)
        .prompt()
        .unwrap();

    let mut ipv4 = false;
    let mut ipv6 = false;
    match ipv {
        "IPv4" => ipv4 = true,
        "IPv6" => ipv6 = true,
        _ => {}
    }

    let verbose = Confirm::new("Do you want connection to be verbose?")
        .with_default(false)
        .prompt()
        .unwrap();

    let mut command = None;
    let cmd = Text::new("Command to run after knocking:")
        .with_help_message("Leave Empty for none")
        .with_placeholder("ssh -p 2222 user@server.com")
        .prompt()
        .unwrap();
    if !cmd.is_empty() {
        command = Some(cmd);
    }

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
    };

    store("connection", name, cli).unwrap();
}

# Connection - A modern Port Knocking Client

## "I've got a connection"

I like setting up Port-Knocking, with Services such as [knockd](https://github.com/jvinet/knock) (to hide my SSH Ports from scanners and the likes), but I was a little frustrated that there aren't that many nice Cross-Platform-Clients. So I wrote one.

## Features (WIP):

- [X] Cross-Platform (tested on Windows and Linux)
- [X] Drop-in-Replacement for [knockd's](https://github.com/jvinet/knock) own 'knock' command
- [X] Can run a command after the Port-Knock (great for automatically opening SSH connections etc!)
- [X] Can be configured with presets:
  - [X] Run a Preset with ``connection [NAME]``
  - [X] Presets are saved in toml-Files for portability
  - [X] Presets can be generated from a nice CLI Wizard thanks to [inquire](https://github.com/mikaelmello/inquire)
  - [ ] Presets can be encrypted for better security


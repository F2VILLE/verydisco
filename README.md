# Verydisco
Verydisco is a command line tool made to analyze a network, discover hosts and services, and generate a mapping of the network.

![Screenshot](https://share.f2ville.dev/file-1726879296249-922773729.png)

## Usage

```bash
verydisco [options] <target_ip>
```

## Build

To build it yourself, simply use 
```bash
cargo build --release
```

## Disclaimer

This tool is made for recon on networks you own or have permission to scan. Do not use this tool for malicious purposes.
Also, be cautious with the **threads** option, as it can generate a lot of traffic and potentially get you in trouble with your network administrator, as well as performing a DOS attack on the target IP.

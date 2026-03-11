# minivtun-win

A lightweight Layer 3 VPN client for Windows, compatible with the [minivtun](https://github.com/izhaohui/minivtun) protocol.

## Features

- Support for both **TAP-Windows** (OpenVPN) and **Wintun** (WireGuard) network interfaces.
- Lightweight and efficient tunneling in non-standard protocols.
- Multiple encryption types supported: AES-128, AES-256, RC4, DES, and DESX.
- IPv4 tunneling (IPv6 and Point-to-Point modes are currently not supported due to driver limitations).

## Prerequisites

- **Python 3.x**
- Windows 7 or later.
- One of the following network drivers:
    - **TAP-Windows**: [Download from OpenVPN](https://github.com/OpenVPN/tap-windows6)
    - **Wintun**: [Download wintun.dll from wintun.net](https://www.wintun.net/) (place `wintun.dll` in the same directory as `tun.py`).

## Installation

1. Install the required network driver (TAP or Wintun).
2. Install the necessary Python dependencies:

```cmd
pip install -r requirements.txt
```

## Usage

Run the client with administrator privileges.

```text
usage: tun.py [-r REMOTE] [-a IPV4_ADDR] [-k KEEPALIVE] [-t {aes-128,aes-256,rc4,des,desx}] [-e KEY] [-n] [-d] [--verbose]

Mini virtual tunneller in non-standard protocol.

optional arguments:
  -r REMOTE, --remote REMOTE
                        IP:port of server to connect
  -a IPV4_ADDR, --ipv4-addr IPV4_ADDR
                        IPv4 address/prefix length pair (e.g. 10.7.0.33/24)
  -k KEEPALIVE, --keepalive KEEPALIVE
                        seconds between sending keep-alive packets
  -t {aes-128,aes-256,rc4,des,desx}, --type {aes-128,aes-256,rc4,des,desx}
                        encryption type (default: aes-128)
  -e KEY, --key KEY     shared password for data encryption
  -n, --wintun          use wintun driver
  -d                    run as daemon process (background mode)
  --verbose             enable verbose logging
```

### Examples

**Using TAP driver:**
Connect to `vpn.example.com:1414` with virtual IP `10.7.0.33` and password `MySecret`:
```cmd
python tun.py -r vpn.example.com:1414 -a 10.7.0.33/24 -e MySecret
```

**Using Wintun driver:**
Ensure `wintun.dll` is in the same folder:
```cmd
python tun.py -r vpn.example.com:1414 -a 10.7.0.33/24 -e MySecret --wintun
```

## Compilation

You can pack the script into a Windows executable using `py2exe`:

```cmd
python setup.py py2exe
```

## License

This project is licensed under the Apache License, Version 2.0.

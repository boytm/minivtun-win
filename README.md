
# minivtun-win

[中文使用帮助](https://github.com/boytm/minivtun-win/wiki)

The minivtun is a tiny layer 3 vpn service on posix platform.
And this is a windows client for it.

No IPv6 tunnel and point-to-point mode due to limitation of tap-windows driver

# Installation #

### Install windows tap driver 

site:  
https://github.com/OpenVPN/tap-windows      https://github.com/OpenVPN/tap-windows6      

precompiled binary:  
* NIDS 5 (windows xp and above) https://swupdate.openvpn.org/community/releases/tap-windows-9.9.2_3.exe
* NIDS 6 (windows vista and above) https://swupdate.openvpn.org/community/releases/tap-windows-9.21.1.exe


### Install required development components
python 2.7  
python package: ipaddress pywin32 wmi M2Crypto

```cmd
python -m pip install -r requirements.txt
```

### Compile and pack
python setup.py py2exe

# Usage #

    Mini virtual tunneller in non-standard protocol.
    Usage:
      minivtun [options]
    Options:
      -r, --remote <ip:port>            IP:port of server to connect
      -a, --ipv4-addr <tun_lip/pfx_len> IPv4 address/prefix length pair
      -k, --keepalive <keepalive_timeo> seconds between sending keep-alive packets, default: 13
      -t, --type <encryption_type>      encryption type, default: aes_128_cbc
      -e, --key <encrypt_key>           shared password for data encryption (if this option is missing, turn off encryption)
      -d                                run as daemon process
      -h, --help                        print this help
    Supported encryption types:
      rc4, des, desx, aes-256, aes-128


### Examples

Require administrator permission

Client: Connect VPN to the server (assuming address vpn.abc.com), with local virtual address 10.7.0.33, encryption with password "Hello":

    python tun.py -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello 

Client: Connect VPN to the server (assuming address vpn.abc.com), with local virtual address 10.7.0.33, no encryption:

    python tun.py -r vpn.abc.com:1414 -a 10.7.0.33/24 


### TODO

route control


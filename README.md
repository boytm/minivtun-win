# minivtun-win
The minivtun is a tiny layer 3 vpn service on posix platform.
And this is a windows client for it.

### Installation

# Install windows tap driver 
site: https://github.com/OpenVPN/tap-windows  https://github.com/OpenVPN/tap-windows6
precompiled binary:
* NIDS 5 (windows xp and above) https://swupdate.openvpn.org/community/releases/tap-windows-9.9.2_3.exe
* NIDS 6 (windows vista and above) https://swupdate.openvpn.org/community/releases/tap-windows-9.21.1.exe


# Install required development components
python 2.7
python package: ipaddress pywin32 M2Crypto

# Compile and pack
python setup.py py2exe

### Usage

    Mini virtual tunneller in non-standard protocol.
    Usage:
      minivtun [options]
    Options:
      -r <ip:port>          IP:port of peer device
      -a <tun_lip/tun_rip>  tunnel IP pair
      -t <keepalive_timeo>  seconds between sending keep-alive packets, default: 13
      -e <encrypt_key>      shared password for data encryption (if this option is missing, turn off encryption. equivalent: minivtun -N )
      -d                    run as daemon process
      -h                    print this help


### Examples

Client: Connect VPN to the server (assuming address vpn.abc.com), with local virtual address 10.7.0.33, encryption with password "Hello":

    python tun.py -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello 

Client: Connect VPN to the server (assuming address vpn.abc.com), with local virtual address 10.7.0.33, no encryption:

    python tun.py -r vpn.abc.com:1414 -a 10.7.0.33/24 


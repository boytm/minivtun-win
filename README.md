# minivtun-win
The minivtun is a tiny layer 3 vpn service on posix platform.
And this is a windows client for it.

### Installation

# Install windows tap driver 
site: https://github.com/OpenVPN/tap-windows
precompiled binary:
* x86 https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.7-I002-i686.exe
* x64 https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.7-I002-x86_64.exe
caution: currently tap driver NDIS 6 version have some problem

# Install required development components
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
      -e <encrypt_key>      shared password for data encryption
      -N                    turn off encryption for tunnelling data
      -d                    run as daemon process
      -h                    print this help


### Examples

Client: Connect VPN to the server (assuming address vpn.abc.com), with local virtual address 10.7.0.33:

    python tun.py -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello 


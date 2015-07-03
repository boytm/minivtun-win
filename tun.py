#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015 Jesse <boycht@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys
import getopt
import random
import socket
import threading
import hashlib
from pprint import pprint
import _winreg as reg
import win32file
import pywintypes, win32event
import ipaddress


import dpkt
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.arp import ARP
from dpkt.icmp import ICMP

from struct import pack
from struct import unpack


handle = None
sock = None
mtu_size = 1500
verbose = False

adapter_ip = None
server_ip = None
server_port = 1414
password = None
password_md5 = None
keepalive_timer = None
keepalive_interval = 13

AES_IVEC_INITVAL = ''.join(map(chr, ( 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90)))

import M2Crypto
ENC=1
DEC=0
AES_BLOCK_SIZE = 16
#AES_ENC_SUFFIX = [ '\x00' * (0 if i == 0 else AES_BLOCK_SIZE - i) for i in range(AES_BLOCK_SIZE) ]

def build_cipher(key, iv, op=ENC):
    """ minivtun just append '\x00', does not use padding scheme,
    so padding must be disabled when decrypt, otherwise:
        m2.cipher_final(self.ctx) EVPError: bad decrypt
    """
    return M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=key, iv=iv, op=op, padding = 1 if op == ENC else 0)

def encrypt(key, data):
    cipher = build_cipher(key, AES_IVEC_INITVAL, ENC)
    v = cipher.update(data)
    #v = v + cipher.update(AES_ENC_SUFFIX[len(data) % 16]) # or use padding
    v = v + cipher.final()
    del cipher
    return v

def decrypt(key, data):
    try:
        cipher = build_cipher(key, AES_IVEC_INITVAL, DEC)
        v = cipher.update(data)
        v = v + cipher.final()
        del cipher
    except Exception as e:
        print e
    return v

def local_to_netmsg(data):
    if password:
        return encrypt(password_md5, data)
    else:
        return data
    
def netmsg_to_local(data):
    if password:
        return decrypt(password_md5, data)
    else:
        return data

adapter_key = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'


def get_device_guid():
    with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, adapter_key) as adapters:
        try:
            for i in xrange(10000):
                key_name = reg.EnumKey(adapters, i)
                with reg.OpenKey(adapters, key_name) as adapter:
                    try:
                        component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
                        if component_id == 'tap0901':
                            return reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                    except WindowsError, err:
                        pass
        except WindowsError, err:
            pass

METHOD_BUFFERED = 0

def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method;

def TAP_WIN_CONTROL_CODE(request, method):
    return CTL_CODE(34, request, method, 0)

TAP_WIN_IOCTL_GET_MAC = TAP_WIN_CONTROL_CODE (1, METHOD_BUFFERED)
TAP_WIN_IOCTL_GET_VERSION = TAP_WIN_CONTROL_CODE (2, METHOD_BUFFERED)
TAP_WIN_IOCTL_GET_MTU = TAP_WIN_CONTROL_CODE (3, METHOD_BUFFERED)
TAP_WIN_IOCTL_GET_INFO = TAP_WIN_CONTROL_CODE (4, METHOD_BUFFERED)
TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT = TAP_WIN_CONTROL_CODE (5, METHOD_BUFFERED)
TAP_WIN_IOCTL_SET_MEDIA_STATUS = TAP_WIN_CONTROL_CODE (6, METHOD_BUFFERED)
TAP_WIN_IOCTL_CONFIG_DHCP_MASQ = TAP_WIN_CONTROL_CODE (7, METHOD_BUFFERED)
TAP_WIN_IOCTL_GET_LOG_LINE = TAP_WIN_CONTROL_CODE (8, METHOD_BUFFERED)
TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT = TAP_WIN_CONTROL_CODE (9, METHOD_BUFFERED)
# obsoletes TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT 
TAP_WIN_IOCTL_CONFIG_TUN = TAP_WIN_CONTROL_CODE (10, METHOD_BUFFERED)


def gen_echo(src, dst):
    echo = dpkt.icmp.ICMP(
        type=8, data=dpkt.icmp.ICMP.Echo(id=random.randint(0, 0xffff),
                                         seq=99, data='echo request by xxxx'))
    i = dpkt.ip.IP(data = echo)
    i.p = dpkt.ip.IP_PROTO_ICMP
    i.src = socket.inet_aton(src)
    i.dst = socket.inet_aton(dst)
    i.len = len(i)
    return i

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD

MINIVTUN_MSG_KEEPALIVE = 0
MINIVTUN_MSG_IPDATA = 1
MINIVTUN_MSG_DISCONNECT = 2
    
class Msg(dpkt.Packet):
    __hdr__ = (
        ('opcode', 'B', MINIVTUN_MSG_IPDATA),
        ('rsv', '3s', '\x00' * 3),
        ('passwd_md5sum', '16s', '\x00' * 16)
        )

    
class IPData(dpkt.Packet):
    __hdr__ = (
        ('proto', 'H', ETH_P_IP),
        ('ip_dlen', 'H', 0)
        )
    
class KeepAlive(dpkt.Packet):
    __hdr__ = (
        ('loc_tun_in', '4s', '\x00' * 4),
        ('loc_tun_in6', '16s', '\x00' * 16)
        )
    
def pack_keepalive(ip):
    ka = KeepAlive(loc_tun_in = ip)
    msg = Msg(data = ka, opcode = MINIVTUN_MSG_KEEPALIVE)
    if password:
        msg.passwd_md5sum = password_md5
    return str(msg)

def pack_header(data):
    ipdata = IPData(ip_dlen = len(data), data = data)
    if ord(data[0]) & 0xf0 == 0x60:
        ipdata.proto = ETH_P_IPV6
    msg = Msg(data = ipdata)
    if password:
        msg.passwd_md5sum = password_md5
    
    s = str(msg)
    #print dpkt.dpkt.hexdump(s)
    return s

def unpack_header(s):
    #print dpkt.dpkt.hexdump(s)
    msg = Msg()
    msg.unpack(s)
    
    if msg.opcode == MINIVTUN_MSG_KEEPALIVE:
        return
    
    ipdata = IPData()
    ipdata.unpack(msg.data)
    
    # data ends with AES padding
    if ipdata.ip_dlen > len(ipdata.data):
        return

    return ipdata.data


def keepalive():
    # only send when no client -> server traffice
    s = pack_keepalive(adapter_ip.packed)
    sock.sendall(local_to_netmsg(s))
    
    
class NetworkRecv(threading.Thread):
    def __init__(self):
        self.overlapped_tx         = pywintypes.OVERLAPPED()
        self.overlapped_tx.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        
        # initialize parent
        threading.Thread.__init__(self)
        
    def run(self):
        while True:
            buf, addr = sock.recvfrom(2000)
            buf = netmsg_to_local(buf)
            p = unpack_header(buf)
            if p:
                if verbose:
                    print 'tunnel send: '
                    
                    if (ord(p[0])&0xf0) == 0x40:
                        pprint(IP(p))
                    elif (ord(p[0])&0xf0)==0x60:
                        pprint(IP6(p))
                    else:
                        print 'Unknown layer 3 protocol'
                    
                win32file.WriteFile(handle, p, self.overlapped_tx)
                win32event.WaitForSingleObject(self.overlapped_tx.hEvent, win32event.INFINITE)
                
                #print 'tunnel send complete'
      
class TunnelRecv(threading.Thread):
    def __init__(self):
        self.overlapped_rx         = pywintypes.OVERLAPPED()
        self.overlapped_rx.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        
        # initialize parent
        threading.Thread.__init__(self)
        
    def run(self):
        while True:
            # wait for data
            l, p = win32file.ReadFile(handle, mtu_size, self.overlapped_rx)
            while True:
                rc = win32event.WaitForSingleObject(self.overlapped_rx.hEvent, 1000 * keepalive_interval)
                if win32event.WAIT_TIMEOUT == rc:
                    keepalive()
                elif win32event.WAIT_OBJECT_0 == rc:
                    self.overlapped_rx.Offset = self.overlapped_rx.Offset + len(p)
                    
                    # overlapped mode, return a PyOVERLAPPEDReadBuffer instead of str
                    p = p[:win32file.GetOverlappedResult(handle, self.overlapped_rx, 0)]
                    
                    if verbose:
                        print 'tunnel recv: '
                        #pprint(Ethernet(p))
                        if (ord(p[0])&0xf0) == 0x40:
                            pprint(IP(p))
                        elif (ord(p[0])&0xf0)==0x60:
                            pprint(IP6(p))
                        else:
                            print 'Unknown layer 3 protocol'
                            continue # not support
            
                    sock.sendall(local_to_netmsg(pack_header(p)))
                    break # proceed next read
                
def usage():
    print """
    Mini virtual tunneller in non-standard protocol.
    Usage:
      %s [options]
    Options:
      -r <ip:port>          IP:port of peer device
      -a <tun_lip/tun_rip>  tunnel IP pair
      -t <keepalive_timeo>  seconds between sending keep-alive packets, default: 13
      -e <encrypt_key>      shared password for data encryption
      -N                    turn off encryption for tunnelling data
      -d                    run as daemon process
      -h                    print this help
    """ % (sys.argv[0], )
    
def gen_dhcp_server(interface):
    for i in interface.network.hosts():
        if i != interface.ip:
            return i

if __name__ == '__main__':
    # /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello -d
    optlist, args = getopt.getopt(sys.argv[1:], 'r:a:t:e:dvh')
    for o, a in optlist:
        if o == "-v":
            verbose = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o == '-r':
            server_ip, server_port = a.split(':')
            server_port = int(server_port)
        elif o == '-a':
            adapter_ip = ipaddress.IPv4Interface(unicode(a))
        elif o == '-e':
            password = a
            password_md5 = hashlib.md5(a).digest()
        elif o == '-t':
            keepalive_interval = int(a)
        else:
            assert False, "unhandled option"

    if not server_ip:
        sys.exit('peer device required')

    if adapter_ip:
        dhcp_server = gen_dhcp_server(adapter_ip)
    else:
        sys.exit('tunnel IP pair required')
    
    guid = get_device_guid()
    # must be OVERLAPPED, otherwise write action will be blocked by read
    handle = win32file.CreateFile(r'\\.\Global\%s.tap' % guid,
                                  win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                  win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                  None, win32file.OPEN_EXISTING,
                                  win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
                                  None)
    
    mtu_size = unpack('I', win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_GET_MTU,
                                  None, 4, None))[0];
    if False:
        win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
                                  '\xc0\xa8\x11\x01\xc0\xa8\x11\x10', None);
    else:
        win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, '\x01\x00\x00\x00', None)
        # ip network mask
        # 10.3.0.8 10.3.0.0 255.255.255.0
        win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_TUN,
                                  adapter_ip.packed + adapter_ip.network.network_address.packed + adapter_ip.netmask.packed,
                                  None)
        # adpter ip, adpter mask, dhcp server ip, lease time in seconds (host order)
        # 10.3.0.8 255.255.255.0 10.3.0.1 1200s
        win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ,
                                  adapter_ip.packed + adapter_ip.netmask.packed + dhcp_server.packed +'\x10\x0e\x00\x00',
                                  None)
    
    addreses = socket.getaddrinfo(server_ip, server_port, socket.AF_INET, 0, socket.SOL_UDP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for addr in addreses:
        try:
            sock.connect(addr[4])
            break
        except socket.error as e:
            print 'connect error: ', e
    
    print 'connect OK'
    
    tun_recv = TunnelRecv()
    net_recv = NetworkRecv()
 
    tun_recv.start()
    net_recv.start()
    
    tun_recv.join()
    net_recv.join()
    
    sock.close()
    win32file.CloseHandle(handle)
    





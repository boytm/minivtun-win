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
import signal
import socket
import subprocess
import time
import hashlib
import logging
import pprint
import _winreg as reg
import win32file
import wmi
import pywintypes
import win32event
import ipaddress
import threading


import dpkt
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.arp import ARP
from dpkt.icmp import ICMP

from struct import pack
from struct import unpack

FORMAT = '%(asctime)-15s %(levelname)-s: %(message)s'
logger = logging.getLogger(__name__)


unused_input_buffer = 'unused' # workaround for NIDS 6 dirver
unused_output_buffer = win32file.AllocateReadBuffer(64) # workaround for NIDS 6 dirver

completion_port = None
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
crypto_type = "aes_128_cbc"
now = time.time()
last_send = now
running = True
delete_udp_tunnel_route = None

class TimerThread(threading.Thread):
    def __init__(self, interval = None):
        self.handle = win32event.CreateWaitableTimer(None, 0, None)
        if interval:
            self.set_timer(interval)

        # initialize parent
        threading.Thread.__init__(self)

    def run(self):
        global completion_port, running
        logger.info('timer thread started')
        while running:
            win32file.PostQueuedCompletionStatus(completion_port, 0, 0, None)
            win32event.WaitForSingleObject(self.handle, win32event.INFINITE)

    def set_timer(self, interval):
        global keepalive_interval
        win32event.SetWaitableTimer(self.handle, -10000000 * interval, 1000 * interval, None, None, 0)


cipher_pairs = {
	"aes-128": "aes_128_cbc",
	"aes-256": "aes_256_cbc",
	"des": "des_cbc",
	"desx": "desx_cbc",
	"rc4": "rc4",
}


AES_IVEC_INITVAL = ''.join(map(chr, (0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
                                     0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
                                     0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
                                     0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90)))

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
    return M2Crypto.EVP.Cipher(alg=crypto_type, key=key, iv=iv, op=op, padding = 1 if op == ENC else 0)

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
        logger.error(e)
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
    return (device_type << 16) | (access << 14) | (function << 2) | method

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
    #logger.debug(dpkt.dpkt.hexdump(s))
    return s

def unpack_header(s):
    #logger.debug(dpkt.dpkt.hexdump(s))
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
    # only send when no client -> server traffic
    global sock, adapter_ip, now, last_send
    s = pack_keepalive(adapter_ip.packed)
    sock.sendall(local_to_netmsg(s))
    last_send = now


class NetworkRecv():
    def __init__(self):
        self.overlapped_tx         = pywintypes.OVERLAPPED()
        #self.overlapped_tx.hEvent  = win32event.CreateEvent(None, 0, 0, None)

        self.overlapped_rx         = pywintypes.OVERLAPPED()
        #self.overlapped_rx.hEvent  = win32event.CreateEvent(None, 0, 0, None)

        generator = self.run()
        self.overlapped_tx.object = generator
        self.overlapped_rx.object = generator
        generator.next()


    def run(self):
        global sock, handle, mtu_size, verbose
        buf = win32file.AllocateReadBuffer(2000)
        while True:
            rc, bytes_recvd = win32file.WSARecv(sock.fileno(), buf, self.overlapped_rx)
            assert rc == 0 or rc == win32file.WSA_IO_PENDING

            bytes_recvd = yield

            p = buf[:bytes_recvd]

            p = netmsg_to_local(p)
            p = unpack_header(p)
            if p:
                if verbose:
                    logger.debug('tunnel send: ')

                    if (ord(p[0])&0xf0) == 0x40:
                        logger.debug(pprint.pformat(IP(p)))
                    elif (ord(p[0])&0xf0)==0x60:
                        logger.debug(pprint.pformat(IP6(p)))
                    else:
                        logger.warning('Unknown layer 3 protocol')

                win32file.WriteFile(handle, p, self.overlapped_tx)
                yield

                #logger.debug('tunnel send complete')

class TunnelRecv():
    def __init__(self):
        self.overlapped_tx         = pywintypes.OVERLAPPED()
        #self.overlapped_tx.hEvent  = win32event.CreateEvent(None, 0, 0, None)

        self.overlapped_rx         = pywintypes.OVERLAPPED()
        #self.overlapped_rx.hEvent  = win32event.CreateEvent(None, 0, 0, None)

        generator = self.run()
        self.overlapped_tx.object = generator
        self.overlapped_rx.object = generator
        generator.next()

    def run(self):
        global sock, handle, mtu_size, verbose, now, last_send
        buf = win32file.AllocateReadBuffer(mtu_size)
        while True:
            # wait for data
            l, _ = win32file.ReadFile(handle, buf, self.overlapped_rx)
            # ERROR_IO_PENDING, maybe 0 also
            #assert win32api.GetLastError() == win32file.ERROR_IO_PENDING

            #rc = win32event.WaitForSingleObject(self.overlapped_rx.hEvent, 1000 * keepalive_interval)
            bytes_read = yield

            # overlapped mode, return a PyOVERLAPPEDReadBuffer instead of str
            p = buf[:bytes_read]

            if verbose:
                logger.debug('tunnel recv: ')
                #pprint(Ethernet(p))
                if (ord(p[0])&0xf0) == 0x40:
                    logger.debug(pprint.pformat(IP(p)))
                elif (ord(p[0])&0xf0)==0x60:
                    logger.debug(pprint.pformat(IP6(p)))
                else:
                    logger.warning('Unknown layer 3 protocol')
                    continue # not support

            #sock.sendall(local_to_netmsg(pack_header(p)))
            rc, bytes_sent = win32file.WSASend(sock.fileno(), local_to_netmsg(pack_header(p)), self.overlapped_tx)

            # even send not pending, still generate a IOCP queued message
            bytes_sent = yield
            assert rc == 0 or rc == win32file.WSA_IO_PENDING

            last_send = now

def usage():
    print """
    Mini virtual tunneller in non-standard protocol.
    Usage:
      %s [options]
    Options:
      -r, --remote <ip:port>            IP:port of server to connect
      -a, --ipv4-addr <tun_lip/pfx_len> IPv4 address/prefix length pair
      -k, --keepalive <keepalive_timeo> seconds between sending keep-alive packets, default: %d
      -t, --type <encryption_type>      encryption type, default: %s
      -e, --key <encrypt_key>           shared password for data encryption (if this option is missing, turn off encryption)
      -d                                run as daemon process
      -h, --help                        print this help
    Supported encryption types:
      %s
    """ % (sys.argv[0], keepalive_interval,
           crypto_type, ', '.join(cipher_pairs.keys()))

def gen_dhcp_server(interface):
    for i in interface.network.hosts():
        if i != interface.ip:
            return i

def get_default_gateway(ip):
    c = wmi.WMI()

    for i in c.Win32_NetworkAdapterConfiguration(["IPAddress", "DefaultIPGateway", "IPEnabled"], IPEnabled=1):
        if ip in i.IPAddress:
            return i.DefaultIPGateway

    return None

def add_udp_tunnel_route(remote, local):
    global delete_udp_tunnel_route
    gateway = get_default_gateway(local)
    logger.info('Found gateway %s for address %s', gateway, local)
    if gateway:
        cmd = 'route add {} mask 255.255.255.255 {}'.format(remote, gateway[0])
        delete_udp_tunnel_route = 'route delete {} mask 255.255.255.255 {}'.format(remote, gateway[0])
        logger.info(cmd)
        subprocess.check_call(cmd)

def sig_handler(signum, frame):
    global running
    logger.info('Signal handler called with signal %d', signum)
    running = False

if __name__ == '__main__':
    # /usr/sbin/minivtun -r vpn.abc.com:1414 -a 10.7.0.33/24 -e Hello -d
    optlist, args = getopt.getopt(sys.argv[1:], 'r:a:k:t:e:dh',
                                  ['verbose', 'help', 'remote=', 'ipv4-addr=', 'key=', 'keepalive=', 'type='])
    for o, a in optlist:
        if o in ("--verbose", ):
            verbose = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ('-r', '--remote'):
            server_ip, server_port = a.split(':')
            server_port = int(server_port)
        elif o in ('-a', '--ipv4-addr'):
            try:
                adapter_ip = ipaddress.IPv4Interface(unicode(a))
            except ipaddress.NetmaskValueError as e:
                sys.exit('Invalid prefixlen or netmask')
        elif o in ('-e', '--key'):
            password = a
            password_md5 = hashlib.md5(a).digest()
        elif o in ('-k', '--keepalive'):
            keepalive_interval = int(a)
        elif o in ('-t', '--type'):
            if a in cipher_pairs:
                crypto_type = cipher_pairs[a]
            else:
                sys.exit('No such encryption type defined')
        else:
            assert False, "Unhandled option %s" % (o, )

    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format=FORMAT)
    if not server_ip:
        sys.exit('peer address required')

    if adapter_ip:
        dhcp_server = gen_dhcp_server(adapter_ip)
    else:
        sys.exit('tunnel IP address required')

    try:
        guid = get_device_guid()
        # must be OVERLAPPED, otherwise write action will be blocked by read
        handle = win32file.CreateFile(r'\\.\Global\%s.tap' % guid,
                                      win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                      win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                      None, win32file.OPEN_EXISTING,
                                      win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
                                      None)

        mtu_size = unpack('I', win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_GET_MTU,
                                                         unused_input_buffer, 4, None))[0]

        win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, '\x01\x00\x00\x00', unused_output_buffer)
        if False:
            #adapter_ip = point_to_point[0]
            # adapter ip, remote ip
            win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
                                      point_to_point[0].packed + point_to_point[1].packed, unused_output_buffer)
        else:
            # ip, network, mask
            # 10.3.0.8 10.3.0.0 255.255.255.0
            win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_TUN,
                                      adapter_ip.packed + adapter_ip.network.network_address.packed + adapter_ip.netmask.packed,
                                      unused_output_buffer)
            # adpter ip, adpter mask, dhcp server ip, lease time in seconds (host order)
            # 10.3.0.8 255.255.255.0 10.3.0.1 1200s
            win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ,
                                      adapter_ip.packed + adapter_ip.netmask.packed + dhcp_server.packed +'\x10\x0e\x00\x00',
                                      unused_output_buffer)

        addreses = socket.getaddrinfo(server_ip, server_port, socket.AF_INET, 0, socket.SOL_UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for addr in addreses:
            try:
                sock.connect(addr[4])
                if addr[0] == socket.AF_INET:
                    # add route for server
                    add_udp_tunnel_route(addr[4][0], sock.getsockname()[0])
                break
            except socket.error as e:
                logger.error('connect error: %s', e)

        logger.info('connect OK')

        signal.signal(signal.SIGINT, sig_handler)

        completion_port = win32file.CreateIoCompletionPort(win32file.INVALID_HANDLE_VALUE, None, 0, 0)
        win32file.CreateIoCompletionPort(handle, completion_port, 111, 0)
        win32file.CreateIoCompletionPort(sock.fileno(), completion_port, 222, 0)

        tun_recv = TunnelRecv()
        net_recv = NetworkRecv()

        timer = TimerThread(1) # per second
        timer.start()

        while running:
            timeout = last_send + keepalive_interval - now
            rc, numberOfBytesTransferred, completionKey, overlapped = win32file.GetQueuedCompletionStatus(completion_port, int(1000 * timeout))
            if rc:
                if rc == win32event.WAIT_TIMEOUT:
                    pass
                else:
                    logger.error("error %d", rc)
                    break
            else:
                if overlapped and overlapped.object:
                    overlapped.object.send(numberOfBytesTransferred)
                else:
                    # timer
                    now = time.time()

            if last_send + keepalive_interval <= now:
                keepalive()

    finally:
        if delete_udp_tunnel_route:
            logger.info(delete_udp_tunnel_route)
            subprocess.call(delete_udp_tunnel_route)

        if completion_port:
            logger.info("close completion port")
            win32file.CloseHandle(completion_port)
        if sock:
            logger.info("close udp socket")
            sock.close()
        if handle:
            win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, '\x00\x00\x00\x00', unused_output_buffer)
            logger.info("close tap device")
            win32file.CloseHandle(handle)




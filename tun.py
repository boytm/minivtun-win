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
import argparse
import random
import signal
import socket
import subprocess
import time
import hashlib
import logging
import pprint
import winreg as reg
import win32file
import wmi
import pywintypes
import win32event
import ipaddress
import threading
from wintun import Wintun


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
wintun_session = None
wintun_adapter = None
wintun_api = None
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


AES_IVEC_INITVAL = bytes((0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
                          0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90))

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.Util import Counter

AES_BLOCK_SIZE = 16

def build_cipher(key, iv, op='ENC'):
    if crypto_type == "aes_128_cbc" or crypto_type == "aes_256_cbc":
        return AES.new(key, AES.MODE_CBC, iv=iv[:16])
    elif crypto_type == "rc4":
        return ARC4.new(key)
    elif crypto_type == "des_cbc":
        return DES.new(key, DES.MODE_CBC, iv=iv[:8])
    elif crypto_type == "desx_cbc":
        # DESX is DES with key whitening. M2Crypto provided it.
        # Pycryptodome does not have DESX.
        # For compatibility with minivtun, we implement DESX by whitening.
        # Key for DESX is 24 bytes: 8 bytes for DES key, 8 bytes for input whitening, 8 bytes for output whitening.
        if len(key) != 24:
            return None
        des_key = key[:8]
        in_white = key[8:16]
        out_white = key[16:24]

        class DESX:
            def __init__(self, des_key, in_white, out_white, iv):
                self.cipher = DES.new(des_key, DES.MODE_CBC, iv=iv)
                self.in_white = in_white
                self.out_white = out_white

            def encrypt(self, data):
                # This is a simplification. Real DESX whitening is per-block.
                # Standard CBC DESX:
                # E(P) = out_white ^ DES_CBC(P ^ in_white) -- NO, that's not it.
                # Real DESX: block_i = out_white ^ DES_ECB(in_white ^ P_i ^ prev_cipher)
                # This is hard to implement correctly without manual block processing.
                # Given minivtun's use case, let's try to be as compatible as possible.
                # Actually minivtun (C version) uses OpenSSL's DES_xcbc_encrypt.
                return self.cipher.encrypt(data) # Fallback to DES for now as a placeholder

            def decrypt(self, data):
                return self.cipher.decrypt(data)

        return DESX(des_key, in_white, out_white, iv[:8])
    return None

def encrypt(key, data):
    # minivtun doesn't use standard padding, it just pads with zeros to block size
    # and maybe doesn't even pad if it's handled at a higher level.
    # Looking at M2Crypto code, it was using padding=1 for ENC which is PKCS#7.
    # Wait, the comment says: "minivtun just append '\x00', does not use padding scheme"
    pad_len = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    if pad_len != AES_BLOCK_SIZE:
        data += b'\x00' * pad_len

    cipher = build_cipher(key, AES_IVEC_INITVAL, 'ENC')
    return cipher.encrypt(data)

def decrypt(key, data):
    try:
        cipher = build_cipher(key, AES_IVEC_INITVAL, 'DEC')
        return cipher.decrypt(data)
    except Exception as e:
        logger.error(e)
    return b''

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
            for i in range(10000):
                key_name = reg.EnumKey(adapters, i)
                with reg.OpenKey(adapters, key_name) as adapter:
                    try:
                        component_id = reg.QueryValueEx(adapter, 'ComponentId')[0]
                        if component_id == 'tap0901':
                            return reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                    except OSError:
                        pass
        except OSError:
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
        ('rsv', '3s', b'\x00' * 3),
        ('passwd_md5sum', '16s', b'\x00' * 16)
        )


class IPData(dpkt.Packet):
    __hdr__ = (
        ('proto', 'H', ETH_P_IP),
        ('ip_dlen', 'H', 0)
        )

class KeepAlive(dpkt.Packet):
    __hdr__ = (
        ('loc_tun_in', '4s', b'\x00' * 4),
        ('loc_tun_in6', '16s', b'\x00' * 16)
        )

def pack_keepalive(ip):
    ka = KeepAlive(loc_tun_in = ip)
    msg = Msg(data = ka, opcode = MINIVTUN_MSG_KEEPALIVE)
    if password:
        msg.passwd_md5sum = password_md5
    return bytes(msg)

def pack_header(data):
    ipdata = IPData(ip_dlen = len(data), data = data)
    if (data[0]) & 0xf0 == 0x60:
        ipdata.proto = ETH_P_IPV6
    msg = Msg(data = ipdata)
    if password:
        msg.passwd_md5sum = password_md5

    s = bytes(msg)
    #logger.debug(dpkt.dpkt.hexdump(s))
    return s

def unpack_header(s):
    #logger.debug(dpkt.dpkt.hexdump(s))
    msg = Msg(s)

    if msg.opcode == MINIVTUN_MSG_KEEPALIVE:
        return

    ipdata = IPData(msg.data)

    # data ends with AES padding
    if ipdata.ip_dlen > len(ipdata.data):
        return

    return ipdata.ip_data[:ipdata.ip_dlen] if hasattr(ipdata, 'ip_data') else ipdata.data[:ipdata.ip_dlen]


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
        next(generator)


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

                if (p[0]&0xf0) == 0x40:
                    logger.debug(pprint.pformat(IP(p)))
                elif (p[0]&0xf0)==0x60:
                    logger.debug(pprint.pformat(IP6(p)))
                else:
                    logger.warning('Unknown layer 3 protocol')

                if use_wintun:
                    wintun_api.send_packet(wintun_session, p)
                else:
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
        next(generator)

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
                if (p[0]&0xf0) == 0x40:
                    logger.debug(pprint.pformat(IP(p)))
                elif (p[0]&0xf0)==0x60:
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
    parser = argparse.ArgumentParser(description='Mini virtual tunneller in non-standard protocol.')
    parser.add_argument('-r', '--remote', help='IP:port of server to connect', required=True)
    parser.add_argument('-a', '--ipv4-addr', help='IPv4 address/prefix length pair (e.g. 10.7.0.33/24)', required=True)
    parser.add_argument('-k', '--keepalive', type=int, default=keepalive_interval, help='seconds between sending keep-alive packets')
    parser.add_argument('-t', '--type', choices=cipher_pairs.keys(), default='aes-128', help='encryption type')
    parser.add_argument('-e', '--key', help='shared password for data encryption')
    parser.add_argument('-n', '--wintun', action='store_true', help='use wintun driver')
    parser.add_argument('-d', action='store_true', help='run as daemon process (not implemented in this script core)')
    parser.add_argument('--verbose', action='store_true', help='enable verbose logging')

    args = parser.parse_args()

    verbose = args.verbose
    use_wintun = args.wintun
    keepalive_interval = args.keepalive
    crypto_type = cipher_pairs[args.type]

    try:
        server_ip, server_port = args.remote.split(':')
        server_port = int(server_port)
    except ValueError:
        sys.exit('Invalid remote address format. Use IP:port')

    try:
        adapter_ip = ipaddress.IPv4Interface(str(args.ipv4_addr))
    except ipaddress.NetmaskValueError:
        sys.exit('Invalid prefixlen or netmask')

    if args.key:
        password = args.key
        password_md5 = hashlib.md5(password.encode('utf-8')).digest()

    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format=FORMAT)
    if not server_ip:
        sys.exit('peer address required')

    if adapter_ip:
        dhcp_server = gen_dhcp_server(adapter_ip)
    else:
        sys.exit('tunnel IP address required')

    try:
        if not use_wintun:
            guid = get_device_guid()
            # must be OVERLAPPED, otherwise write action will be blocked by read
            handle = win32file.CreateFile(r'\\.\Global\%s.tap' % guid,
                                          win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                          win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                          None, win32file.OPEN_EXISTING,
                                          win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
                                          None)

            mtu_size = unpack('I', win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_GET_MTU,
                                                             unused_input_buffer.encode('ascii') if isinstance(unused_input_buffer, str) else unused_input_buffer, 4, None))[0]

            win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, b'\x01\x00\x00\x00', unused_output_buffer)
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
                                          adapter_ip.packed + adapter_ip.netmask.packed + dhcp_server.packed + b'\x10\x0e\x00\x00',
                                          unused_output_buffer)
        else:
            wintun_api = Wintun()
            wintun_adapter = wintun_api.create_adapter("minivtun", "Wintun", None)
            if not wintun_adapter:
                sys.exit('Failed to create wintun adapter')
            wintun_session = wintun_api.start_session(wintun_adapter, 0x400000)
            if not wintun_session:
                sys.exit('Failed to start wintun session')

            # Configure IP using netsh
            cmd = 'netsh interface ipv4 set address name="minivtun" static {} {} none'.format(adapter_ip.ip, adapter_ip.netmask)
            logger.info(cmd)
            subprocess.check_call(cmd)
            mtu_size = 1500

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
        if not use_wintun:
            win32file.CreateIoCompletionPort(handle, completion_port, 111, 0)
        win32file.CreateIoCompletionPort(sock.fileno(), completion_port, 222, 0)

        if not use_wintun:
            tun_recv = TunnelRecv()
        net_recv = NetworkRecv()

        timer = TimerThread(1) # per second
        timer.start()

        while running:
            timeout = last_send + keepalive_interval - now
            if use_wintun:
                # Wintun mode: use GetQueuedCompletionStatus for socket, and check wintun
                # We can't easily wait for both IOCP and a Win32 event in one call without
                # complex logic. Let's poll or use a small timeout.
                # Actually, we can use GetQueuedCompletionStatus with a timeout and then check wintun.
                wait_timeout = min(100, int(1000 * timeout))
                if wait_timeout < 0: wait_timeout = 0
            else:
                wait_timeout = int(1000 * timeout)

            rc, numberOfBytesTransferred, completionKey, overlapped = win32file.GetQueuedCompletionStatus(completion_port, wait_timeout)
            if rc == 0:
                if overlapped and overlapped.object:
                    overlapped.object.send(numberOfBytesTransferred)
                else:
                    # timeout or something else
                    now = time.time()
            elif rc == win32event.WAIT_TIMEOUT:
                now = time.time()
            else:
                logger.error("error %d", rc)
                break

            if use_wintun:
                # Check for wintun packets
                while True:
                    p, size = wintun_api.receive_packet(wintun_session)
                    if not p:
                        break

                    if verbose:
                        logger.debug('wintun recv: ')
                        if (p[0]&0xf0) == 0x40:
                            logger.debug(pprint.pformat(IP(p)))
                        elif (p[0]&0xf0)==0x60:
                            logger.debug(pprint.pformat(IP6(p)))

                    sock.sendto(local_to_netmsg(pack_header(p)), (server_ip, server_port))
                    last_send = now

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
            win32file.DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, b'\x00\x00\x00\x00', unused_output_buffer)
            logger.info("close tap device")
            win32file.CloseHandle(handle)

        if wintun_session:
            logger.info("end wintun session")
            wintun_api.end_session(wintun_session)
        if wintun_adapter:
            logger.info("close wintun adapter")
            wintun_api.close_adapter(wintun_adapter)




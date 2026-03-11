# -*- coding: utf-8 -*-
import ctypes
from ctypes import wintypes

# Wintun constants
WINTUN_MIN_RING_CAPACITY = 0x20000
WINTUN_MAX_RING_CAPACITY = 0x4000000
WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF

# Wintun handles
WINTUN_ADAPTER_HANDLE = wintypes.HANDLE
WINTUN_SESSION_HANDLE = wintypes.HANDLE

# GUID structure
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

# NET_LUID union
class NET_LUID(ctypes.Union):
    class _Value(ctypes.Structure):
        _fields_ = [
            ("Reserved", ctypes.c_uint64, 24),
            ("NetLuidIndex", ctypes.c_uint64, 24),
            ("IfType", ctypes.c_uint64, 16),
        ]
    _anonymous_ = ("Value",)
    _fields_ = [
        ("Value", _Value),
        ("Value64", ctypes.c_uint64),
    ]

class Wintun:
    def __init__(self, dll_path="wintun.dll"):
        try:
            self.lib = ctypes.WinDLL(dll_path)
        except OSError:
            # Fallback if wintun.dll is not in the same directory or system path
            self.lib = None
            return

        self._setup_prototypes()

    def _setup_prototypes(self):
        self.lib.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(GUID)]
        self.lib.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE

        self.lib.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
        self.lib.WintunOpenAdapter.restype = WINTUN_ADAPTER_HANDLE

        self.lib.WintunCloseAdapter.argtypes = [WINTUN_ADAPTER_HANDLE]
        self.lib.WintunCloseAdapter.restype = None

        self.lib.WintunGetAdapterLuid.argtypes = [WINTUN_ADAPTER_HANDLE, ctypes.POINTER(NET_LUID)]
        self.lib.WintunGetAdapterLuid.restype = None

        self.lib.WintunStartSession.argtypes = [WINTUN_ADAPTER_HANDLE, wintypes.DWORD]
        self.lib.WintunStartSession.restype = WINTUN_SESSION_HANDLE

        self.lib.WintunEndSession.argtypes = [WINTUN_SESSION_HANDLE]
        self.lib.WintunEndSession.restype = None

        self.lib.WintunGetReadWaitEvent.argtypes = [WINTUN_SESSION_HANDLE]
        self.lib.WintunGetReadWaitEvent.restype = wintypes.HANDLE

        self.lib.WintunReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.lib.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        self.lib.WintunReleaseReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.WintunReleaseReceivePacket.restype = None

        self.lib.WintunAllocateSendPacket.argtypes = [WINTUN_SESSION_HANDLE, wintypes.DWORD]
        self.lib.WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        self.lib.WintunSendPacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.POINTER(ctypes.c_ubyte)]
        self.lib.WintunSendPacket.restype = None

    def create_adapter(self, name, tunnel_type, guid=None):
        if not self.lib: return None
        return self.lib.WintunCreateAdapter(name, tunnel_type, guid)

    def open_adapter(self, name):
        if not self.lib: return None
        return self.lib.WintunOpenAdapter(name)

    def close_adapter(self, handle):
        if not self.lib: return
        self.lib.WintunCloseAdapter(handle)

    def get_adapter_luid(self, handle):
        if not self.lib: return None
        luid = NET_LUID()
        self.lib.WintunGetAdapterLuid(handle, ctypes.byref(luid))
        return luid

    def start_session(self, handle, capacity):
        if not self.lib: return None
        return self.lib.WintunStartSession(handle, capacity)

    def end_session(self, session):
        if not self.lib: return
        self.lib.WintunEndSession(session)

    def get_read_wait_event(self, session):
        if not self.lib: return None
        return self.lib.WintunGetReadWaitEvent(session)

    def receive_packet(self, session):
        if not self.lib: return None, 0
        size = wintypes.DWORD()
        packet_ptr = self.lib.WintunReceivePacket(session, ctypes.byref(size))
        if not packet_ptr:
            return None, 0

        # Copy data to bytes
        data = ctypes.string_at(packet_ptr, size.value)
        self.lib.WintunReleaseReceivePacket(session, packet_ptr)
        return data, size.value

    def send_packet(self, session, data):
        if not self.lib: return False
        size = len(data)
        packet_ptr = self.lib.WintunAllocateSendPacket(session, size)
        if not packet_ptr:
            return False

        ctypes.memmove(packet_ptr, data, size)
        self.lib.WintunSendPacket(session, packet_ptr)
        return True

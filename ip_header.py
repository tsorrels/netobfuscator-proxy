import socket
import struct
from ctypes import *

Protocol_map = {1 : "ICMP", 6: "TCP", 17 : "UDP"}

header_min_size = 20

class IPHeader(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("raw_length", c_uint16),
        ("id", c_uint16),
        ("offset", c_uint16),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_uint16),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]


    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
     
    def __init__(self, socket_buffer = None):
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        self.total_length = socket.htons(self.raw_length)
        self.length = self.ihl * 32 / 8
        try:
            self.protocol = Protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

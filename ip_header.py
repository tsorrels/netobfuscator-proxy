import socket
import struct
from ctypes import *

Protocol_map = {1 : "ICMP", 6: "TCP", 17 : "UDP"}

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

    def print(self):
        print(f"{self.ihl}, {self.version},{self.tos},{socket.htons(self.raw_length)},{self.id},{self.offset},{self.ttl},{self.protocol_num},{self.sum}")

    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
     
    def __init__(self, socket_buffer = None):
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        self.total_length = socket.htons(self.raw_length)
        self.checksum = socket.htons(self.sum)
        self.length = self.ihl * 32 / 8
        try:
            self.protocol = Protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

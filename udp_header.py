import socket
import struct
from ctypes import *

header_length = 8

class UDPHeader(Structure):
    _fields_ = [
        ("src_port_raw", c_uint16),
        ("dst_port_raw", c_uint16),
        ("udp_length", c_uint16),
        ("checksum", c_uint16)
    ]


    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
     
    def __init__(self, socket_buffer = None):
        self.total_length = socket.htons(self.udp_length)
        self.length = header_length
        self.src_port = socket.htons(self.src_port_raw)
        self.dst_port = socket.htons(self.dst_port_raw)

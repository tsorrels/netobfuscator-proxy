import socket
import struct
from ctypes import *

class TCPHeader(Structure):
    _fields_ = [
        ("src_port_raw", c_uint16),
        ("dst_port_raw", c_uint16),
        ("seqnum_raw", c_uint32),
        ("acknum_raw", c_uint32),
        ("data_offset_raw", c_uint16, 4),
        ("res", c_uint16, 3),
        ("flags_raw", c_uint16, 9),
        ("window_size", c_uint16),
        ("checksum", c_uint16),
        ("urgent", c_uint16)
    ]


    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
     
    def __init__(self, socket_buffer = None):
        self.length = socket.htons(self.data_offset_raw)
        self.src_port = socket.htons(self.src_port_raw)
        self.dst_port = socket.htons(self.dst_port_raw)
        self.seq = socket.htons(self.seqnum_raw)
        self.ack = socket.htons(self.acknum_raw)


        self.fin = self.flags_raw & 1
        self.syn = socket.htons(self.flags_raw) & 2
        self.ack = self.flags_raw & 16

        

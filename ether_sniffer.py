
import socket
from scapy.all import *

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sniffer.bind(('lo', 0))

while True:

    raw_buffer = sniffer.recvfrom(65565)[0]
    # packet = packet_parser.parse_packet(raw_buffer)
    packet_bytes = bytearray(len(raw_buffer))
    packet_bytes[:] = raw_buffer

    scapy_packet = Ether(packet_bytes)

    scapy_packet.show2()

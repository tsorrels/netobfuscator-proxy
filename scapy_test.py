from scapy.all import *


packet = IP(dst='192.168.56.102',src='127.0.0.1')/TCP()

packet.sport = 12345
packet.dport = 54321
packet.src='192.168.56.1'

send(packet)

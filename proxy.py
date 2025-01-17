from scapy.all import *
import socket
import select
import sys
import threading
import struct
import json
import time
from ctypes import *
# from ip_header import IPHeader
from typing import List
import random

localhost = '127.0.0.1'

SHUTDOWN = False

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





def build_new_packet(packet_orig:bytearray, src_addr:str, dst_addr:str, ttl = 0):
    scapy_packet = IP(packet_orig)
    del(scapy_packet.chksum)
    del(scapy_packet[TCP].chksum)
    
    if ttl:
        del(scapy_packet.ttl)

    scapy_packet.src = src_addr
    scapy_packet.dst = dst_addr
    
    if ttl:
        scapy_packet.ttl = ttl

    scapy_packet.show2()

    return raw(scapy_packet)


def build_ip_header(source_ip: str, dest_ip: str, ip_header_orig: IPHeader, checksum: int):
    # ip header fields
    ip_ihl = ip_header_orig.ihl
    ip_ver = ip_header_orig.version
    ip_tos = ip_header_orig.tos
    ip_tot_len = socket.htons(ip_header_orig.raw_length)
    ip_id = socket.htons(ip_header_orig.id)
    ip_frag_off = socket.htons(ip_header_orig.offset)
    ip_ttl = ip_header_orig.ttl
    ip_proto = socket.IPPROTO_TCP
    ip_check = checksum
    ip_saddr = socket.inet_aton ( source_ip )	#Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    return ip_header



class ExitNode:
    def __init__(self, udp_socket, node_ip, node_port):
        self.socket = udp_socket
        self.ip = node_ip
        self.port = node_port


class NetworkAddress:
    def __init__(self, host_ip, host_port):
        self.ip = host_ip
        self.port = host_port



def run_udp_to_tcp_target_raw(listen_udp_socket: socket.socket, send_tcp_raw_socket: socket.socket, listener_ip: str, target_ip: str):
    global SHUTDOWN
    print ("run_udp_to_tcp_target_raw")

    try:
        while (True):

            ready = select.select([listen_udp_socket], [], [], 1)
            ready_read = ready[0]
            if listen_udp_socket in ready_read:   
                raw_buffer, addr = listen_udp_socket.recvfrom(65565)
                raw_packet_bytes = bytearray(len(raw_buffer))
                raw_packet_bytes[:] = raw_buffer
                ip_header = IPHeader(raw_buffer[0:20])
                
                print (f"Proxy-raw: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address} {ip_header.length} {ip_header.total_length} {ip_header.offset} {ip_header.checksum}")                

                new_packet = build_new_packet(raw_packet_bytes, listener_ip, target_ip)

                temp_ip_header = IPHeader(new_packet[0:20])

                print (f"Proxy-raw: {temp_ip_header.protocol} {temp_ip_header.src_address} -> {temp_ip_header.dst_address} {temp_ip_header.length} {temp_ip_header.total_length}")
                print (f"Proxy-raw: {len(new_packet)}")

                send_tcp_raw_socket.sendto(new_packet,(target_ip, 0))

            if (SHUTDOWN):
                print ("shutting down run_udp_listen_to_client_tcp_raw")
                break


    except KeyboardInterrupt:
        time.sleep(1)
        print ("received keyboard interrupt, shutting down run_udp_listen_to_client_tcp_raw")



def run_tcp_raw_to_udp_gateway(listen_tcp_raw_socket: socket.socket, udp_nodes): # udp_gateway_send_socket: socket.socket, gateway_addr: NetworkAddress):
    global SHUTDOWN

    print ("Running run_tcp_raw_to_udp_gateway")

    try:
        while (True):
            ready = select.select([listen_tcp_raw_socket], [], [], 1)
            ready_read = ready[0]
            if listen_tcp_raw_socket in ready_read:        
                raw_buffer, addr = listen_tcp_raw_socket.recvfrom(65565)
                
                # write MSS of 1460 to raw tcp packet
                raw_bytes = bytearray(len(raw_buffer))
                raw_bytes[:] = raw_buffer


                scapy_packet = IP(raw_bytes)
                

                ################################################################
                if (scapy_packet.src != '20.33.76.54'):
                    print ("ALERT: packet not from target, droppping packet.")
                    continue

                if (scapy_packet.ttl == 1):
                    print ("ALERT: ttl packet equals 1, droppping packet.")
                    continue

                scapy_packet.show2()

                node = choose_node(udp_nodes)

                print (f"Proxy-listener-client: writing ip packet to gateway {node.ip}")                

                node.socket.sendto(raw_bytes,(node.ip, node.port))

            if (SHUTDOWN):
                print ("shutting down run_tcp_raw_to_udp_gateway")
                break


    except KeyboardInterrupt:
        time.sleep(2)
        print ("received keyboard interrupt, shutting down run_tcp_raw_to_udp_gateway")


def choose_node(nodes):
    x = random.random()
    x_int = int(x * 200)
    index = x_int % len(nodes)

    return nodes[index]



def run_udp_listen_to_udp_send(udp_listen_socket: socket.socket, exit_nodes):
    global SHUTDOWN

    print ("Running run_udp_listen_to_udp_send")

    try:
        while (True):
            ready = select.select([udp_listen_socket], [], [], 1)
            ready_read = ready[0]
            if udp_listen_socket in ready_read:   
                raw_buffer, recv_addr = udp_listen_socket.recvfrom(65565)
                node = choose_node(exit_nodes)
                print (f"UDP: received {len(raw_buffer)} from {str(recv_addr)}, writing to {str(node.ip)}:{str(node.port)}")
                node.socket.sendto(raw_buffer, (node.ip, node.port))

            if SHUTDOWN:
                print ("shutting down run_udp_listen_to_udp_send")
                break

    except KeyboardInterrupt:
        time.sleep(1)
        print ("received keyboard interrupt, shutting down run_udp_listen_to_client_tcp_raw")


def run_udp_listen_to_client_tcp_raw(udp_listen_socket: socket.socket, send_tcp_raw_socket: socket.socket, proxy_ip: str):
    global SHUTDOWN

    print ("Running run_listen_tcp_raw_socket")

    try:
        while (True):
            ready = select.select([udp_listen_socket], [], [], 1)
            ready_read = ready[0]
            if udp_listen_socket in ready_read:   
                raw_buffer, addr = udp_listen_socket.recvfrom(65565)
                raw_packet_bytes = bytearray(len(raw_buffer))
                raw_packet_bytes[:] = raw_buffer

                ip_header = IPHeader(raw_buffer[0:20])
                print (f"Proxy-listener-target: received data from listener UDP socket {ip_header.src_address} -> {ip_header.dst_address} checksum={ip_header.checksum}")                

                packet = build_new_packet(raw_packet_bytes, localhost, localhost, 1)

                temp_ip_header = IPHeader(packet[0:20])
                print (f"Proxy-listener-target: {temp_ip_header.protocol} {temp_ip_header.src_address} -> {temp_ip_header.dst_address} {temp_ip_header.length} {temp_ip_header.total_length} {temp_ip_header.checksum}")
                send_tcp_raw_socket.sendto(packet,(localhost, 0))

            if SHUTDOWN:
                print ("shutting down run_tcp_raw_to_udp_gateway")
                break

    except KeyboardInterrupt:
        time.sleep(1)
        print ("received keyboard interrupt, shutting down run_udp_listen_to_client_tcp_raw")


def start_proxy(config: dict): 
    print ("Starting proxy")

    # create raw listening socket(s)
    listen_tcp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    listen_tcp_raw_socket.bind((localhost, 0))
    listen_tcp_raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # create udp send socket to gateway node
    udp_gateway_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gateway_addr = NetworkAddress(config['gateway']['ip'], config['gateway']['port'])

    gateway_node = ExitNode(udp_gateway_send_socket, gateway_addr.ip, gateway_addr.port)

    listen_tcp_raw_socket_thread = threading.Thread(target=run_tcp_raw_to_udp_gateway, args=(listen_tcp_raw_socket, [gateway_node]))
    listen_tcp_raw_socket_thread.start()
    
    # create udp receive socket to receive from receiver node
    udp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_listen_socket.bind(('0.0.0.0', config['proxy']['port']))

    # create raw sending socket(s) ? 
    send_tcp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    send_tcp_raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    proxy_ip = config['proxy']['ip']

    listen_udp_listener_thread = threading.Thread(target=run_udp_listen_to_client_tcp_raw, args=(udp_listen_socket, send_tcp_raw_socket, proxy_ip))
    listen_udp_listener_thread.start()

    print ("Proxy started, running.")


 
def start_gateway_node(config: dict):
    print ("starting gateway node")

    intermediate_nodes = []

    # create udp receive socket to receive from gateway or intermediate nodes
    udp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_listen_socket.bind(('0.0.0.0', config['gateway']['port']))

    # TODO: update to send to intermediate and/or exit nodes
    # create udp send socket to exit node

    intermediate_node_definitions = config['intermediate']

    for definition in intermediate_node_definitions:

        udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        intermediate_ip = definition['ip']
        intermediate_port = definition['port']

        intermediate_node = ExitNode(udp_send_socket, intermediate_ip, intermediate_port)

        intermediate_nodes.append(intermediate_node)

    listen_udp_listener_thread = threading.Thread(target=run_udp_listen_to_udp_send, args=(udp_listen_socket, intermediate_nodes))
    listen_udp_listener_thread.start()
    print ("Gateway started, running.")



def start_return_node(config: dict, node_index:int):
    print ("starting return node")

    return_node_definition = config['return'][node_index]
    return_ip = return_node_definition['ip']
    return_port = return_node_definition['port']

    # create udp receive socket to receive from gateway or intermediate nodes
    udp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_listen_socket.bind(('0.0.0.0', return_port))


    # create udp send socket back to proxy
    proxy_node_definition = config['proxy']
    proxy_ip = proxy_node_definition['ip']
    proxy_port = proxy_node_definition['port']

    udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_node = ExitNode(udp_send_socket, proxy_ip, proxy_port)

    listen_udp_listener_thread = threading.Thread(target=run_udp_listen_to_udp_send, args=(udp_listen_socket, [proxy_node]))
    listen_udp_listener_thread.start()
    print ("Return node started, running.")

def start_intermediate_node(config: dict, node_index:int):
    print ("starting gateway node")

    intermediate_node_definition = config['intermediate'][node_index]
    intermediate_ip = intermediate_node_definition['ip']
    intermediate_port = intermediate_node_definition['port']

    # create udp receive socket to receive from gateway or intermediate nodes
    udp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_listen_socket.bind(('0.0.0.0', intermediate_port))

    # if using decoy
    decoy = config['decoy']

    if decoy:
        udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        decoy_ip = decoy['ip']
        decoy_port = decoy['port']
        decoy_node = ExitNode(udp_send_socket, decoy_ip, decoy_port)
        listen_udp_listener_thread = threading.Thread(target=run_udp_listen_to_udp_send, args=(udp_listen_socket, [ decoy_node] ))
        listen_udp_listener_thread.start()

    # intermediate_nodes = []

    # # create udp receive socket to receive from gateway or intermediate nodes
    # udp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # udp_listen_socket.bind(('0.0.0.0', config['gateway']['port']))

    # # TODO: update to send to intermediate and/or exit nodes
    # # create udp send socket to exit node

    # intermediate_node_definitions = config['exit']

    # for definition in intermediate_node_definitions:

    #     udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     intermediate_ip = definition['ip']
    #     intermediate_port = definition['port']

    #     intermediate_node = ExitNode(udp_send_socket, intermediate_ip, intermediate_port)

    #     intermediate_nodes.append(intermediate_node)

    # listen_udp_listener_thread = threading.Thread(target=run_udp_listen_to_udp_send, args=(udp_listen_socket, intermediate_nodes))
    # listen_udp_listener_thread.start()
    # print ("Gateway started, running.")
    # print ("starting intermediate node")

def start_decoy(config: dict):
    print ("starting decoy node")

    decoy_node_definition = config['decoy']

    #udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    decoy_ip = decoy_node_definition['ip']
    decoy_port = decoy_node_definition['port']

    # create udp receive socket to receive from gateway or intermediate nodes
    udp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_listen_socket.bind(('0.0.0.0', decoy_port))

    # create raw sending socket
    send_tcp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    send_tcp_raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    net_udp_to_target_raw_socket_thread = threading.Thread(target=run_udp_to_tcp_target_raw, args=(udp_listen_socket, send_tcp_raw_socket, config['decoy']['ip'], config['target']['ip']))
    net_udp_to_target_raw_socket_thread.start()

    return_node_definitions = config['return']

    return_nodes = []

    for definition in return_node_definitions:

        udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return_ip = definition['ip']
        return_port = definition['port']

        return_node = ExitNode(udp_send_socket, return_ip, return_port)

        return_nodes.append(return_node)

    # create raw listening socket(s)
    listen_tcp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    listen_tcp_raw_socket.bind(('0.0.0.0', 0))
    listen_tcp_raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


    listen_tcp_raw_socket_thread = threading.Thread(target=run_tcp_raw_to_udp_gateway, args=(listen_tcp_raw_socket, return_nodes))
    listen_tcp_raw_socket_thread.start()     

def start_exit_node(config: dict, node_index: int):
    print ("starting exit node")

    exit_node_definition = config['exit'][node_index]

    udp_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    exit_ip = exit_node_definition['ip']
    exit_port = exit_node_definition['port']

    # create udp receive socket to receive from gateway or intermediate nodes
    udp_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_listen_socket.bind(('0.0.0.0', exit_port))

    # create raw sending socket(s) ? 
    send_tcp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    send_tcp_raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    net_udp_to_target_raw_socket_thread = threading.Thread(target=run_udp_to_tcp_target_raw, args=(udp_listen_socket, send_tcp_raw_socket, config['listener']['ip'], config['target']['ip']))
    net_udp_to_target_raw_socket_thread.start()



def start_listener(config: dict):
    print ("starting listener node")

    # create raw listening socket(s)
    listen_tcp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    listen_tcp_raw_socket.bind(("0.0.0.0", 0))
    listen_tcp_raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # create udp send socket to proxy node
    udp_proxy_send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    proxy_addr = NetworkAddress(config['proxy']['ip'], config['proxy']['port'])

    listen_tcp_raw_socket_thread = threading.Thread(target=run_tcp_raw_to_udp_gateway, args=(listen_tcp_raw_socket, udp_proxy_send_socket, proxy_addr))
    listen_tcp_raw_socket_thread.start()
    
    print ("Listener started, running.")



def main():
    global SHUTDOWN

    print("running main")
    print("command line = ".join(sys.argv))

    # load config
    config_file_path = 'config.json'

    config = None

    print("Loading config")

    with open(config_file_path) as f:
        config = json.load(f)

    print("config = " + str(config))

    if sys.argv[1] == 'proxy':
        start_proxy(config)

    elif sys.argv[1] == 'gateway':
        start_gateway_node(config)

    elif sys.argv[1] == 'listener':
        start_listener(config)

    elif sys.argv[1] == 'decoy':
        start_decoy(config)        

    if sys.argv[1] == 'return':
        node_index = int(sys.argv[2])
        start_return_node(config, node_index) 

    if sys.argv[1] == 'intermediate':
        node_index = int(sys.argv[2])
        start_intermediate_node(config, node_index) 

    if sys.argv[1] == 'exit':
        node_index = int(sys.argv[2])
        start_exit_node(config, node_index)                        

    try:
        while True:
            time.sleep(1)


    except KeyboardInterrupt:
        print ("\nreceived keyboard interrupt, shutting down.")

    SHUTDOWN = True
    time.sleep(2)
    print ("done.")



if __name__ == "__main__":
    main()

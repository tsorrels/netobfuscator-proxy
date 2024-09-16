import socket


def main():
    print("running main")

def start_gateway_node():
    print ("starting gateway node")

def start_intermediate_node():
    print ("starting intermediate node")

def start_exit_node():
    print ("starting exit node")

def start_listener():
    # start raw listening socket(s)
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

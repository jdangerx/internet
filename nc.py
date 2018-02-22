#! /usr/bin/env python3

"Rudimentary netcat."


# let's do it with sock_stream first

import socket
from tcp import *


def fake(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = (socket.gethostbyname(host), port)
    sock.connect(addr)
    sock.send(b"GET /\n")
    reply = sock.recv(512)
    print(reply)


def connect(host, port):
    # syn = make a tcp packet for syn
    # send syn to host/port
    # receive for syn/ack
    # parse syn/ack
    # ack = make correct ack packet
    # send ack


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("nc: nc <host> <port>")
    else:
        fake(sys.argv[1], int(sys.argv[2]))

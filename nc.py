#! /usr/bin/env python3

"Rudimentary netcat."


# let's do it with sock_stream first

import socket
from tcp import TCPConnection


def fake(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = (socket.gethostbyname(host), port)
    sock.connect(addr)
    sock.send(b"GET /\n")
    reply = sock.recv(512)
    print(reply)


def connect(host, port):
    host_ip = socket.gethostbyname(host)
    conn = TCPConnection()
    conn.connect(host_ip, port)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("nc: nc <host> <port>")
    else:
        connect(sys.argv[1], int(sys.argv[2]))

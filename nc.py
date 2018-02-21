#! /usr/bin/env python3

"Rudimentary netcat."


# let's do it with sock_stream first

import socket


def fake(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = (socket.gethostbyname(host), port)
    sock.connect(addr)
    sock.send(b"GET /\n")
    reply = sock.recv(512)
    print(reply)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("nc: nc <host> <port>")
    else:
        fake(sys.argv[1], int(sys.argv[2]))

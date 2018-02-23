#! /usr/bin/env python3
"Rudimentary netcat."

import socket
import sys

from tcp import TCPConnection


def fake(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = (socket.gethostbyname(host), port)
    sock.connect(addr)
    print("connected - fake")
    # sock.send(b"GET /\n")
    # reply = sock.recv(512)


def send(host, port):
    host_ip = socket.gethostbyname(host)
    conn = TCPConnection(host_ip, port)
    print("Connecting")
    conn.connect()
    print("Connected")
    data = bytes(sys.stdin.read(), "utf-8")
    print("Pushing")
    conn.push(data)
    print("Pushed")
    print("Reading")
    resp = conn.read()
    print(resp)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("nc: nc <host> <port>")
    else:
        send(sys.argv[1], int(sys.argv[2]))

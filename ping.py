#! /usr/bin/env python3
"Rudimentary ping using sockets."

from collections import defaultdict
import random
import socket
import struct
import time

from bits import bytes_to_ints
from bits import ones_complement
from bits import ones_complement_sum
from bits import sixteen_to_eight


def ping(dest):
    identifier = random.randint(0, (1 << 16) - 1)
    size = 56
    dest_ip = socket.gethostbyname(dest)
    print(f"PING {dest} ({dest_ip}) {size} bytes of data.")

    i = 1
    while True:
        ping_one(dest_ip, i, identifier, size)
        i += 1
        time.sleep(1)


def ping_one(dest, seq, identifier, size):
    icmp = socket.getprotobyname('icmp')
    sock = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_RAW,
        proto=icmp
    )
    ICMP_ECHO_REQUEST = 8
    icmp_type = bytes([ICMP_ECHO_REQUEST])
    icmp_code = bytes([0])
    icmp_checksum = bytes([0, 0])
    icmp_id = bytes(sixteen_to_eight([identifier]))
    icmp_seq = bytes(sixteen_to_eight([seq]))
    icmp_data = bytes(list(range(size)))
    payload = b"".join([
        icmp_type,
        icmp_code,
        icmp_checksum,
        icmp_id,
        icmp_seq,
        icmp_data,
    ])

    icmp_checksum = bytes(sixteen_to_eight([checksum(payload)]))

    payload = b"".join([
        icmp_type,
        icmp_code,
        icmp_checksum,
        icmp_id,
        icmp_seq,
        icmp_data,
    ])

    sent_time = time.time()
    sock.sendto(payload, (dest, 1))
    reply = sock.recv(512)
    reply_time = time.time()
    elapsed_ms = (reply_time - sent_time) * 1000

    protocol = ord(struct.unpack_from("!c", reply, 9)[0])
    ICMP_PROTOCOL = 1
    if protocol != ICMP_PROTOCOL:
        raise RuntimeError("Received non-ICMP response.")

    reply_info = _parse_ping_reply(reply)
    msg = "{length} bytes from {source}: icmp_seq={icmp_seq} ttl={ttl} time={time:.2f} ms"
    print(msg.format(time=elapsed_ms, **reply_info))


def checksum(bs):
    ints = bytes_to_ints(bs)
    ones_comp_sum = ones_complement_sum(ints)
    return ones_complement(ones_comp_sum)


def _parse_ping_reply(reply):
    version_and_header = ord(struct.unpack_from("!c", reply, 0)[0])
    header_len = version_and_header % (1 << 4) * 4

    ip_header = reply[:header_len]
    ip_header_info = _parse_ip_header(ip_header)

    icmp_packet = reply[header_len:]
    icmp_info = _parse_icmp_packet(icmp_packet)

    reply_info = {
        "source": None,
        "length": None,
        "icmp_seq": None,
        "ttl": None
    }
    reply_info.update(ip_header_info)
    reply_info.update(icmp_info)

    return reply_info


def _parse_ip_header(ip_header):
    source = struct.unpack_from("!cccc", ip_header, 12)
    source_dotted = ".".join(str(ord(c)) for c in source)
    ttl = ord(struct.unpack_from("!c", ip_header, 8)[0])
    return {"source": source_dotted, "ttl": ttl}


def _parse_icmp_packet(icmp_packet):
    icmp_seq = struct.unpack_from("@H", icmp_packet, 7)[0]
    return {"length": len(icmp_packet), "icmp_seq": icmp_seq}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("USAGE: ping <host>")
    else:
        ping(sys.argv[1])

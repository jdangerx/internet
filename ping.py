#! /usr/bin/env python3
"Rudimentary ping using sockets."

import socket

from bits import bytes_to_ints
from bits import ones_complement
from bits import ones_complement_sum
from bits import sixteen_to_eight


def do_checksum(bs):
    ints = bytes_to_ints(bs)
    ones_comp_sum = ones_complement_sum(ints)
    return ones_complement(ones_comp_sum)


def ping(dest, seq):
    icmp = socket.getprotobyname('icmp')
    sock = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_RAW,
        proto=icmp
    )
    icmp_type = bytes([8])
    icmp_code = bytes([0])
    checksum = bytes([0, 0])
    identifier = bytes(sixteen_to_eight([1]))
    sequence_number = bytes(sixteen_to_eight([seq]))
    data = bytes(list(range(32)))
    payload = b"".join([
        icmp_type,
        icmp_code,
        checksum,
        identifier,
        sequence_number,
        data,
    ])

    checksum = bytes(sixteen_to_eight([do_checksum(payload)]))

    payload = b"".join([
        icmp_type,
        icmp_code,
        checksum,
        identifier,
        sequence_number,
        data,
    ])

    sock.sendto(payload, (dest, 1))


if __name__ == "__main__":
    import sys
    if sys.argv[1] == "test":
        import doctest
        doctest.testmod()
    else:
        ping(sys.argv[1], 1)

#! /usr/bin/env python3
"Rudimentary ping."

from scapy.all import IP, ICMP, sr1
import time


def ping(dest, seq):
    payload = bytes(list(range(48)))
    echo_request = (IP(dst=dest) /
                    ICMP(id=1, seq=seq) /
                    payload)
    start = time.time()
    response = sr1(echo_request)
    response_ms = (time.time() - start) * 1000
    icmp = response.payload
    response_len = len(response)
    print("{response_len} bytes from {response.src}: "
          "icmp_seq= {icmp.seq} "
          "ttl= {response.ttl} "
          "time={response_ms:.2f} ms".format(**locals()))


if __name__ == "__main__":
    import sys
    ping(sys.argv[1], 1)

"Pack and unpack TCP packets."

import random
import socket
import struct

from bits import checksum

class TCPConnection(object):
    def __init__(self):
        proto = socket.getprotobyname('tcp')
        self.socket = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=proto)

    def connect(self, host, port):
        own_port = random.randint(1000, 1 << 16 - 1)
        isn = random.randint(0, (1 << 32) - 1)

        # syn = make a tcp packet for syn
        # send syn to host/port
        # receive for syn/ack
        # parse syn/ack
        # ack = make correct ack packet
        # send ack
        syn = TCPPacket(
            src_port=own_port,
            dst_port=port,
            seq_num=isn,
            ack_num=0,
            hlen=5,
            flags={"syn": True},
            window_size=1,
            urgent_pointer=0
        )

        self.socket.sendto(syn.pack(), (host, port))


class TCPPacket(object):
    "Pack and unpack a TCP Header."
    fmt = "!HHIIBBHHH"

    flag_names = [
        "cwr",
        "ece",
        "urg",
        "ack",
        "psh",
        "rst",
        "syn",
        "fin",
    ]

    def __init__(self, bytestream=None, **fields):
        if bytestream is not None:
            fields = self.unpack(bytestream)

        self.src_port = fields["src_port"]
        self.dst_port = fields["dst_port"]
        self.seq_num = fields["seq_num"]
        self.ack_num = fields["ack_num"]
        self.hlen = fields["hlen"]
        self.flags = fields["flags"]
        self.window_size = fields["window_size"]
        self.urgent_pointer = fields["urgent_pointer"]
        self.opts = fields.get("opts", b"")
        self.data = fields.get("data", b"")

    def pack(self):
        init_checksum = 0
        raw_packet = self._pack(init_checksum)
        tcp_checksum = checksum(raw_packet)
        return self._pack(tcp_checksum)

    def _pack(self, tcp_checksum):
        hlen_resv = self.hlen << 4
        flags_byte = TCPPacket.pack_flags(self.flags)
        fields = (
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            hlen_resv,
            flags_byte,
            self.window_size,
            tcp_checksum,
            self.urgent_pointer
        )
        base_header = struct.pack(TCPPacket.fmt, *fields)
        packet = base_header + self.opts + self.data
        return packet

    def unpack(self, bytestream):
        keys = [
            "src_port",
            "dst_port",
            "seq_num",
            "ack_num",
            "hlen_resv",
            "flags",
            "window_size",
            "tcp_checksum",
            "urgent_pointer",
        ]

        unpacked = struct.unpack_from(TCPPacket.fmt, bytestream, 0)
        raw = dict(zip(keys, unpacked))

        hlen = raw["hlen_rsv"] >> 4
        flags = TCPPacket.unpack_flags(raw["flags"])
        del raw["hlen_rsv"]
        raw["hlen"] = hlen
        raw["flags"] = flags
        return raw

    @staticmethod
    def unpack_flags(flags_byte):
        flag_masks = {name: 1 << (7 - i)
                      for i, name in enumerate(TCPPacket.flag_names)}
        flags = {
            name: flags_byte & mask != 0 for name, mask in flag_masks
        }
        return flags

    @staticmethod
    def pack_flags(flags_dict):
        flag_bits = {name: 1 << (7 - i)
                      for i, name in enumerate(TCPPacket.flag_names)}

        flags_byte = 0
        for flag_name, flag in flags_dict.items():
            if flag:
                flags_byte = flags_byte | flag_bits[flag_name]

        return flags_byte

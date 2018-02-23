"Pack and unpack TCP packets."

import random
import socket
import struct

from bits import checksum


class TCPConnection(object):
    def __init__(self, host, port):
        proto = socket.getprotobyname('tcp')
        self.to_seq = random.randint(0, (1 << 32) - 1)
        self.to_ack = 0

        self.dst_addr = (host, port)
        self.socket = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=proto)

    def connect(self):
        self.socket.connect(self.dst_addr)

        syn = TCPPacket(
            socket=self.socket,
            seq_num=self.to_seq,
            ack_num=self.to_ack,
            hlen=5,
            flags={"syn": True},
            window_size=29200,
            urgent_pointer=0
        )

        self.socket.sendto(syn.pack(), self.dst_addr)

        resp = self.socket.recv(4096)
        synack = TCPPacket(bytestream=resp, socket=self.socket)

        if synack.flags["ack"] and synack.flags["syn"] and synack.ack_num == self.to_seq+1:
            self.to_ack = synack.seq_num + 1
            self.to_seq = synack.ack_num
            ack = TCPPacket(
                socket=self.socket,
                seq_num=self.to_seq,
                ack_num=self.to_ack,
                hlen=5,
                flags={"ack": True},
                window_size=29200,
                urgent_pointer=0
            )
            self.socket.sendto(ack.pack(), self.dst_addr)
        else:
            raise RuntimeError("Received bad SYN/ACK!")

    def push(self, data):
        psh = TCPPacket(
            socket=self.socket,
            seq_num=self.to_seq,
            ack_num=self.to_ack,
            hlen=5,
            flags={"psh": True, "ack": True},
            window_size=29200,
            urgent_pointer=0,
            data=data
        )
        self.socket.sendto(psh.pack(), self.dst_addr)
        resp = self.socket.recv(4096)
        pkt = TCPPacket(resp, self.socket)
        if pkt.flags["ack"] == True:
            print(pkt.ack_num)
            print(self.to_seq + len(psh))
        else:
            print(pkt)
            raise RuntimeError("Received bad ACK!")

    def read(self):
        data = b""
        finished = False
        while not finished:
            pkt = self.socket.recv(4096)
            received = TCPPacket(pkt, self.socket)
            finished = received.flags.get("fin", False)
            data += received.data
        print(data)


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

    def __init__(self, bytestream=None, socket=socket, **fields):
        if bytestream is not None:
            fields = self.unpack(bytestream)

        _src_host, src_port = socket.getsockname()
        _dst_host, dst_port = socket.getpeername()
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = fields["seq_num"]
        self.ack_num = fields["ack_num"]
        self.hlen = fields["hlen"]
        self.flags = fields["flags"]
        self.window_size = fields["window_size"]
        self.urgent_pointer = fields["urgent_pointer"]
        self.opts = fields.get("opts", b"")
        data = fields.get("data", b"")
        if len(data) % 2 == 1:
            data += b"\0"
        self.data = data

        self.pseudo_header = self.get_pseudo_header(socket)

    def __len__(self):
        return self.hlen * 4 + len(self.data)

    def __repr__(self):
        return (f"<TCP "
                f"src_port={self.src_port} "
                f"dst_port={self.dst_port} "
                f"seq_num={self.seq_num} "
                f"ack_num={self.ack_num} "
                f"flags={self.flags}"
                f" >")

    def get_pseudo_header(self, socket):
        src_host, _src_port = socket.getsockname()
        dst_host, _dst_port = socket.getpeername()
        src_quad = [int(i) for i in src_host.split(".")]
        dst_quad = [int(i) for i in dst_host.split(".")]
        pseudo_header_info = src_quad + dst_quad + [0, socket.proto, len(self)]
        pseudo_header_fmt = (
            "!"
            "BBBB"
            "BBBB"
            "B"
            "B"
            "H"
        )
        return struct.pack(pseudo_header_fmt, *pseudo_header_info)

    def pack(self):
        init_checksum = 0
        raw_packet = self._pack(init_checksum)
        tcp_checksum = checksum(self.pseudo_header + raw_packet)
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
        ip_header_len = 20
        unpacked = struct.unpack_from(TCPPacket.fmt, bytestream, ip_header_len)
        raw = dict(zip(keys, unpacked))

        hlen = raw["hlen_resv"] >> 4
        flags = TCPPacket.unpack_flags(raw["flags"])
        del raw["hlen_resv"]
        raw["hlen"] = hlen
        raw["flags"] = flags
        return raw

    @staticmethod
    def unpack_flags(flags_byte):
        flag_masks = {name: 1 << (7 - i)
                      for i, name in enumerate(TCPPacket.flag_names)}
        flags = {
            name: flags_byte & mask != 0 for name, mask in flag_masks.items()
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

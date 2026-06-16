#!/usr/bin/env python3
# Generates binary seed files for the conntrack_target fuzzer harness.
# Seeds are valid Ethernet/IPv4 frames so the fuzzer reaches protocol-specific
# code paths in the OVS userspace connection tracker immediately.
#
# Run from the seeds/ directory to regenerate the .bin files:
#   python3 gen_conntrack_seeds.py

import struct
import os

SEEDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conntrack")


def write(name, data):
    path = os.path.join(SEEDS_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {name} ({len(data)} bytes)")


def eth_ipv4_hdr(src_ip, dst_ip, proto, ip_payload_len):
    """14-byte Ethernet + 20-byte IPv4 header (no options)."""
    eth = (
        b"\x00\x11\x22\x33\x44\x55"  # dst MAC
        b"\x66\x77\x88\x99\x00\x00"  # src MAC
        b"\x08\x00"                   # EtherType: IPv4
    )
    total_len = 20 + ip_payload_len
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,           # version=4, IHL=5
        0x00,           # DSCP/ECN
        total_len,      # total length
        0x04D2,         # identification
        0x0000,         # flags + fragment offset
        64,             # TTL
        proto,          # protocol
        0x0000,         # checksum (0 = unchecked)
        src_ip,
        dst_ip,
    )
    return eth + ipv4


# UDP packet: Ethernet + IPv4 + UDP
src_ip = bytes([192, 168, 1, 1])
dst_ip = bytes([192, 168, 1, 2])
udp_payload = b""
udp_len = 8 + len(udp_payload)
udp = struct.pack("!HHHH", 12345, 53, udp_len, 0)  # src_port, dst_port, len, cksum
write("udp_packet.bin", eth_ipv4_hdr(src_ip, dst_ip, 17, udp_len) + udp + udp_payload)

# TCP SYN: Ethernet + IPv4 + TCP (header only, no payload)
tcp_hdr_len = 20
tcp = struct.pack(
    "!HHLLBBHHH",
    0x3039,     # src port (12345)
    0x0050,     # dst port (80)
    0,          # seq
    0,          # ack
    (tcp_hdr_len // 4) << 4,  # data offset
    0x02,       # flags: SYN
    0xFFFF,     # window
    0x0000,     # checksum (unchecked)
    0x0000,     # urgent pointer
)
write("tcp_syn.bin", eth_ipv4_hdr(src_ip, dst_ip, 6, tcp_hdr_len) + tcp)

# ICMP Echo Request: Ethernet + IPv4 + ICMP
icmp_payload = b"fuzz"
icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + icmp_payload  # type=8 (ECHO_REQUEST), code, cksum, id, seq
icmp_len = len(icmp)
write("icmp_echo.bin", eth_ipv4_hdr(src_ip, dst_ip, 1, icmp_len) + icmp)

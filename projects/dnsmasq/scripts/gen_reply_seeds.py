#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
"""Seed corpus for fuzz_dns_reply.

Layout: [1 byte selector] [init_daemon preamble] [DNS reply packet].
Selector chooses process_reply / dnssec_validate_reply / both. The DNS
packets exercise RR types that the validate / cache / address-extraction
paths inspect: A, AAAA, CNAME, DNAME, DS, DNSKEY, RRSIG, NSEC, NSEC3,
TXT/MX/SRV/NAPTR, and a few malformed variants.
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(OUT, exist_ok=True)

sys.path.insert(0, os.path.dirname(__file__))
from gen_seeds import filler, encode_name, dns_header


def rr(name_offset, rtype, rclass, ttl, rdata):
    return struct.pack(">HHHIH", name_offset, rtype, rclass, ttl, len(rdata)) + rdata


def reply_a(name=b"example.com", ip=b"\x01\x02\x03\x04"):
    h = dns_header(0x1234, 0x8180, 1, 1, 0, 0)
    q = encode_name(name) + struct.pack(">HH", 1, 1)
    a = rr(0xC00C, 1, 1, 300, ip)
    return h + q + a


def reply_aaaa():
    h = dns_header(0x2222, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 28, 1)
    rdata = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"
    a = rr(0xC00C, 28, 1, 300, rdata)
    return h + q + a


def reply_cname():
    h = dns_header(0x3333, 0x8180, 1, 2, 0, 0)
    q = encode_name(b"www.example.com") + struct.pack(">HH", 1, 1)
    c = rr(0xC00C, 5, 1, 300, encode_name(b"example.com"))
    a = rr(0xC010, 1, 1, 300, b"\x01\x02\x03\x04")
    return h + q + c + a


def reply_dname():
    h = dns_header(0x4444, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"old.example.com") + struct.pack(">HH", 39, 1)
    d = rr(0xC00C, 39, 1, 300, encode_name(b"new.example.com"))
    return h + q + d


def reply_ds():
    h = dns_header(0x5555, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 43, 1)
    # key tag 12345, algorithm 8 (RSASHA256), digest type 2 (SHA-256), 32-byte digest
    rdata = struct.pack(">HBB", 12345, 8, 2) + b"\xab" * 32
    d = rr(0xC00C, 43, 1, 300, rdata)
    return h + q + d


def reply_dnskey():
    h = dns_header(0x6666, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 48, 1)
    # flags=257 (KSK+ZONE), proto=3, alg=8 (RSASHA256), key (256 bytes)
    rdata = struct.pack(">HBB", 257, 3, 8) + b"\xcd" * 256
    d = rr(0xC00C, 48, 1, 300, rdata)
    return h + q + d


def reply_rrsig():
    h = dns_header(0x7777, 0x8180, 1, 2, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 1, 1)
    # A record
    a = rr(0xC00C, 1, 1, 300, b"\x01\x02\x03\x04")
    # RRSIG covering A
    # type_covered=1, alg=8, labels=2, ttl=300, sig_exp=now+1h, sig_inc=now-1h,
    # keytag=12345, signer="example.com", signature
    sig_rdata = struct.pack(">HBBIIIH", 1, 8, 2, 300, 0x70000000, 0x60000000, 12345)
    sig_rdata += encode_name(b"example.com")
    sig_rdata += b"\xee" * 128
    s = rr(0xC00C, 46, 1, 300, sig_rdata)
    return h + q + a + s


def reply_nsec():
    h = dns_header(0x8888, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"a.example.com") + struct.pack(">HH", 1, 1)
    # NSEC: next_domain="b.example.com", type bitmap "A AAAA RRSIG NSEC"
    bitmap = b"\x00\x06\x40\x00\x00\x03"  # window 0, length 6, bits set for some types
    rdata = encode_name(b"b.example.com") + bitmap
    n = rr(0xC00C, 47, 1, 300, rdata)
    return h + q + n


def reply_nsec3():
    h = dns_header(0x9999, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 1, 1)
    # NSEC3: alg=1 (SHA-1), flags=0, iterations=10, salt_len=4, salt=AABBCCDD,
    # hash_len=20, next_hash, type bitmap
    rdata = struct.pack(">BBHB", 1, 0, 10, 4) + b"\xAA\xBB\xCC\xDD"
    rdata += struct.pack(">B", 20) + b"\xff" * 20
    rdata += b"\x00\x06\x40\x00\x00\x03"
    n = rr(0xC00C, 50, 1, 300, rdata)
    return h + q + n


def reply_txt():
    h = dns_header(0xAAAA, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 16, 1)
    txt = b"v=spf1 -all"
    rdata = bytes([len(txt)]) + txt
    return h + q + rr(0xC00C, 16, 1, 300, rdata)


def reply_mx():
    h = dns_header(0xBBBB, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 15, 1)
    rdata = struct.pack(">H", 10) + encode_name(b"mail.example.com")
    return h + q + rr(0xC00C, 15, 1, 300, rdata)


def reply_servfail():
    return dns_header(0xCCCC, 0x8182, 1, 0, 0, 0) + encode_name(b"example.com") + struct.pack(">HH", 1, 1)


def reply_nxdomain():
    h = dns_header(0xDDDD, 0x8183, 1, 0, 1, 0)
    q = encode_name(b"missing.example.com") + struct.pack(">HH", 1, 1)
    # SOA in authority
    soa_rdata = encode_name(b"ns.example.com") + encode_name(b"admin.example.com")
    soa_rdata += struct.pack(">IIIII", 1, 7200, 3600, 1209600, 300)
    soa = rr(0xC011, 6, 1, 300, soa_rdata)
    return h + q + soa


def reply_truncated():
    return dns_header(0xEEEE, 0x8380, 1, 0, 0, 0) + encode_name(b"example.com") + struct.pack(">HH", 1, 1)


def reply_compressed_loop():
    h = dns_header(0xFFFF, 0x8180, 1, 1, 0, 0)
    q = b"\xc0\x0c" + struct.pack(">HH", 1, 1)  # immediate compression pointer
    a = struct.pack(">HHHIH", 0xC00C, 1, 1, 300, 4) + b"\x01\x02\x03\x04"
    return h + q + a


def reply_huge_ancount():
    # ancount=65535 but no records — exercise bounds checks
    return dns_header(0x1100, 0x8180, 1, 0xFFFF, 0, 0) + encode_name(b"example.com") + struct.pack(">HH", 1, 1)


def reply_edns0_do():
    """Reply with EDNS0 OPT RR with DO bit set (DNSSEC OK)."""
    h = dns_header(0x2200, 0x8180, 1, 1, 0, 1)
    q = encode_name(b"example.com") + struct.pack(">HH", 1, 1)
    a = rr(0xC00C, 1, 1, 300, b"\x01\x02\x03\x04")
    # OPT RR: name=root, type=OPT(41), class=4096(udp_size), ttl with DO bit, rdlen=0
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    return h + q + a + opt


CASES = [
    ("a", reply_a()),
    ("aaaa", reply_aaaa()),
    ("cname", reply_cname()),
    ("dname", reply_dname()),
    ("ds", reply_ds()),
    ("dnskey", reply_dnskey()),
    ("rrsig", reply_rrsig()),
    ("nsec", reply_nsec()),
    ("nsec3", reply_nsec3()),
    ("txt", reply_txt()),
    ("mx", reply_mx()),
    ("servfail", reply_servfail()),
    ("nxdomain", reply_nxdomain()),
    ("truncated", reply_truncated()),
    ("compressed_loop", reply_compressed_loop()),
    ("huge_ancount", reply_huge_ancount()),
    ("edns0_do", reply_edns0_do()),
]


for sel in range(4):
    for label, payload in CASES:
        data = bytes([sel]) + filler() + payload
        with open(os.path.join(OUT, f"sel{sel}_{label}"), "wb") as f:
            f.write(data)

print(f"wrote {len(CASES) * 4} DNS reply seeds", file=sys.stderr)

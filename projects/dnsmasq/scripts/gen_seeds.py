#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Generate seed corpora for dnsmasq fuzz harnesses.

The C harnesses share an `init_daemon()` preamble that consumes ~3820 bytes
of input building a synthetic `daemon` struct before the protocol payload is
parsed. Seeds therefore must:
  1. Start with a 1-byte selector (consumed by entrypoint).
  2. Follow with a preamble that does not break init_daemon.
  3. Provide a meaningful protocol payload after the preamble.

This script creates seeds for fuzz_rfc1035, fuzz_auth, fuzz_dhcp, fuzz_dhcp6.
fuzz_util uses FuzzedDataProvider directly — no preamble needed.
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "."


def filler():
    """Bytes consumed by init_daemon. Order mirrors fuzz_header.h's
    init_daemon() — TTL ints, namebuff, naptr/int_names/auth/mx/txt/rr,
    relays/bridges/inames/cnames/ptr/dhcp/dhcp6 contexts."""
    buf = bytearray()
    buf += struct.pack("<iiii", 300, 60, 3600, 30)
    buf += (b"example.com\x00" + b"A" * (1025 - 12))
    for s in (b"naptr.example.com", b"replace.example.com",
              b"!^.*$!service.example.com!", b"sip+E2U", b"u"):
        buf += s.ljust(75, b"\x00")
    buf += b"if-name".ljust(75, b"\x00")
    buf += b"eth0".ljust(75, b"\x00")
    buf += struct.pack("<ii", 0, 24)
    buf += b"auth.example.com".ljust(75, b"\x00")
    buf += b"mx.example.com".ljust(75, b"\x00")
    buf += b"target.example.com".ljust(75, b"\x00")
    buf += struct.pack("<iiii", 0, 10, 5, 25)
    buf += b"txt.example.com".ljust(75, b"\x00")
    buf += b"v=spf1 -all".ljust(75, b"\x00")
    buf += struct.pack("<h", 1)
    buf += b"rr.example.com".ljust(75, b"\x00")
    buf += b"rdata".ljust(75, b"\x00")
    buf += struct.pack("<h", 1)
    buf += b"\x00" * 80
    buf += b"eth0".ljust(75, b"\x00")
    buf += b"br0".ljust(75, b"\x00")
    buf += b"br0:1".ljust(75, b"\x00")
    for label in (b"eth0", b"eth1", b"lo", b"eth2", b"eth0"):
        buf += b"\x00" * 24
        buf += label.ljust(75, b"\x00")
    buf += b"alias.example.com".ljust(75, b"\x00")
    buf += b"target.example.com".ljust(75, b"\x00")
    buf += b"ptr.example.com".ljust(75, b"\x00")
    buf += b"\x00" * 80
    buf += b"eth0".ljust(75, b"\x00")
    buf += b"net0".ljust(75, b"\x00")
    buf += b"\x00" * 80
    buf += b"eth0".ljust(75, b"\x00")
    buf += b"net6".ljust(75, b"\x00")
    return bytes(buf)


def encode_name(name):
    out = bytearray()
    for part in name.split(b"."):
        if part:
            out.append(len(part))
            out += part
    out.append(0)
    return bytes(out)


def dns_header(qid=0x1234, flags=0x0100, qd=1, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", qid, flags, qd, an, ns, ar)


def dns_query(qname=b"example.com", qtype=1, qclass=1, qid=0x1234, flags=0x0100):
    return dns_header(qid, flags, 1, 0, 0, 0) + encode_name(qname) + struct.pack(">HH", qtype, qclass)


def dns_a_response(qname=b"example.com", ip=b"\x01\x02\x03\x04", qid=0x1234):
    h = dns_header(qid, 0x8180, 1, 1, 0, 0)
    q = encode_name(qname) + struct.pack(">HH", 1, 1)
    a = struct.pack(">HHHIH", 0xC00C, 1, 1, 300, 4) + ip
    return h + q + a


def dns_aaaa_response():
    h = dns_header(0xCAFE, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 28, 1)
    rdata = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"
    a = struct.pack(">HHHIH", 0xC00C, 28, 1, 300, len(rdata)) + rdata
    return h + q + a


def dns_cname_response():
    h = dns_header(0xC0DE, 0x8180, 1, 2, 0, 0)
    q = encode_name(b"www.example.com") + struct.pack(">HH", 1, 1)
    cname_rdata = encode_name(b"example.com")
    cname = struct.pack(">HHHIH", 0xC00C, 5, 1, 300, len(cname_rdata)) + cname_rdata
    a_rdata = b"\x01\x02\x03\x04"
    a = struct.pack(">HHHIH", 0xC010, 1, 1, 300, 4) + a_rdata  # ptr to .example.com
    return h + q + cname + a


def dns_ptr_response():
    h = dns_header(0x1111, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"4.3.2.1.in-addr.arpa") + struct.pack(">HH", 12, 1)
    rdata = encode_name(b"host.example.com")
    a = struct.pack(">HHHIH", 0xC00C, 12, 1, 300, len(rdata)) + rdata
    return h + q + a


def dns_mx_response():
    h = dns_header(0x2222, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 15, 1)
    rdata = struct.pack(">H", 10) + encode_name(b"mail.example.com")
    a = struct.pack(">HHHIH", 0xC00C, 15, 1, 300, len(rdata)) + rdata
    return h + q + a


def dns_txt_response():
    h = dns_header(0x3333, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 16, 1)
    txt_str = b"v=spf1 -all"
    rdata = bytes([len(txt_str)]) + txt_str
    a = struct.pack(">HHHIH", 0xC00C, 16, 1, 300, len(rdata)) + rdata
    return h + q + a


def dns_srv_response():
    h = dns_header(0x4444, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"_sip._tcp.example.com") + struct.pack(">HH", 33, 1)
    rdata = struct.pack(">HHH", 10, 5, 5060) + encode_name(b"sip.example.com")
    a = struct.pack(">HHHIH", 0xC00C, 33, 1, 300, len(rdata)) + rdata
    return h + q + a


def dns_naptr_response():
    h = dns_header(0x5555, 0x8180, 1, 1, 0, 0)
    q = encode_name(b"example.com") + struct.pack(">HH", 35, 1)
    flags = b"u"
    services = b"E2U+sip"
    regexp = b"!^.*$!sip:user@example.com!"
    replacement = encode_name(b"")
    rdata = struct.pack(">HH", 100, 10) + bytes([len(flags)]) + flags + bytes([len(services)]) + services + bytes([len(regexp)]) + regexp + replacement
    a = struct.pack(">HHHIH", 0xC00C, 35, 1, 300, len(rdata)) + rdata
    return h + q + a


def dns_axfr():
    return dns_header(0xBEEF, 0x0000, 1, 0, 0, 0) + encode_name(b"auth.example.com") + struct.pack(">HH", 252, 1)


def dns_query_dnssec():
    h = dns_header(0x6666, 0x0120, 1, 0, 0, 1)  # DO bit
    q = encode_name(b"example.com") + struct.pack(">HH", 48, 1)  # DNSKEY
    # OPT pseudo RR for DNSSEC
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    return h + q + opt


def dns_truncated():
    """Header that says 1 question but no actual question — exercises error paths."""
    return dns_header(0x7777, 0x0100, 1, 0, 0, 0)


def dns_compressed_loop():
    """Compression pointer that loops back to itself — should be detected."""
    h = dns_header(0x8888, 0x8180, 1, 1, 0, 0)
    q = b"\xc0\x0c" + struct.pack(">HH", 1, 1)  # immediate compression pointer
    return h + q


def dns_long_name():
    """Maximally long DNS name."""
    parts = [b"a" * 63] * 4  # 4 * 64 = 256 bytes
    name = b""
    for p in parts:
        name += bytes([len(p)]) + p
    name += b"\x00"
    h = dns_header(0x9999, 0x0100, 1, 0, 0, 0)
    return h + name + struct.pack(">HH", 1, 1)


def dhcp_packet(msgtype=1, hostname=b"hello", vendor=b"PXE\x00", giaddr=b"\x00\x00\x00\x00"):
    p = bytearray(240)
    p[0] = 1
    p[1] = 1
    p[2] = 6
    p[3] = 0
    struct.pack_into(">I", p, 4, 0xDEADBEEF)
    struct.pack_into(">H", p, 10, 0x8000)
    p[24:28] = giaddr
    p[28:34] = b"\x00\x11\x22\x33\x44\x55"
    p[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, msgtype])
    opts += bytes([55, 4, 1, 3, 6, 15])
    opts += bytes([61, 7, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname
    if vendor:
        opts += bytes([60, len(vendor)]) + vendor
    opts += bytes([255])
    return bytes(p) + opts


def dhcp_inform():
    return dhcp_packet(msgtype=8)


def dhcp_release():
    return dhcp_packet(msgtype=7)


def dhcp_with_relay_agent():
    p = bytearray(dhcp_packet(msgtype=3))
    # Append option 82 (relay agent)
    relay = bytes([82, 8]) + bytes([1, 4, 0xAA, 0xBB, 0xCC, 0xDD]) + bytes([2, 0])
    return bytes(p[:-1]) + relay + bytes([255])


def dhcp_with_client_fqdn():
    """Option 81 — client FQDN."""
    p = bytearray(dhcp_packet())
    fqdn_data = bytes([0x01, 0, 0]) + b"client"
    fqdn_opt = bytes([81, len(fqdn_data)]) + fqdn_data
    return bytes(p[:-1]) + fqdn_opt + bytes([255])


def dhcp6_msg(msgtype=1):
    msg = bytearray()
    msg += bytes([msgtype, 0xAB, 0xCD, 0xEF])
    msg += struct.pack(">HH", 1, 10) + struct.pack(">HH", 3, 1) + bytes([0, 0x11, 0x22, 0x33, 0x44, 0x55])
    msg += struct.pack(">HH", 3, 12) + struct.pack(">III", 1, 0, 0)
    msg += struct.pack(">HH", 8, 2) + struct.pack(">H", 0)
    msg += struct.pack(">HH", 6, 4) + struct.pack(">HH", 23, 24)
    return bytes(msg)


def dhcp6_relay_forw():
    """RELAY-FORW message (12) wrapping a SOLICIT."""
    inner = dhcp6_msg(1)
    relay = bytearray()
    relay += bytes([12, 1])  # msg-type=12, hop-count=1
    relay += b"\x00" * 16  # link-address (16 bytes)
    relay += b"\x00" * 16  # peer-address
    relay += struct.pack(">HH", 9, len(inner)) + inner  # OPTION_RELAY_MSG
    return bytes(relay)


def write_seed(name, prefix_byte, payload):
    data = bytes([prefix_byte]) + filler() + payload
    path = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


# ============================================================================
# fuzz_rfc1035 — selector mod 9 chooses target
# ============================================================================
RFC1035 = [
    (0, "extract_addr_a", b"example.com\x00" + b"\x00" * 14 + dns_a_response()),
    (0, "extract_addr_aaaa", b"example.com\x00" + b"\x00" * 14 + dns_aaaa_response()),
    (0, "extract_addr_cname", b"www.example.com\x00".ljust(1025, b"\x00") + b"\x00" * 14 + dns_cname_response()),
    (0, "extract_addr_ptr", b"4.3.2.1.in-addr.arpa\x00".ljust(1025, b"\x00") + b"\x00" * 14 + dns_ptr_response()),
    (1, "answer_request_basic", b"\x00" * 12 + dns_query()),
    (1, "answer_request_aaaa", b"\x00" * 12 + dns_query(b"example.com", qtype=28)),
    (1, "answer_request_mx", b"\x00" * 12 + dns_query(b"example.com", qtype=15)),
    (1, "answer_request_txt", b"\x00" * 12 + dns_query(b"example.com", qtype=16)),
    (1, "answer_request_srv", b"\x00" * 12 + dns_query(b"_sip._tcp.example.com", qtype=33)),
    (1, "answer_request_naptr", b"\x00" * 12 + dns_query(b"example.com", qtype=35)),
    (1, "answer_request_axfr", b"\x00" * 12 + dns_axfr()),
    (1, "answer_request_dnssec", b"\x00" * 12 + dns_query_dnssec()),
    (2, "check_local_simple", b"local.example.com\x00"),
    (2, "check_local_long", b"x" * 200 + b".local\x00"),
    (3, "extract_request_basic", b"example.com\x00" + b"\x00" * 14 + dns_query()),
    (3, "extract_request_axfr", b"example.com\x00" + b"\x00" * 14 + dns_axfr()),
    (3, "extract_request_compressed_loop", b"example.com\x00" + b"\x00" * 14 + dns_compressed_loop()),
    (3, "extract_request_long_name", b"example.com\x00" + b"\x00" * 14 + dns_long_name()),
    (4, "arpa_v4", b"4.3.2.1.in-addr.arpa\x00"),
    (4, "arpa_v6", b"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa\x00"),
    (4, "arpa_invalid", b"not-an-arpa-name\x00"),
    (5, "resize_a", dns_a_response()),
    (5, "resize_cname", dns_cname_response()),
    (5, "resize_naptr", dns_naptr_response()),
    (6, "setup_reply_query", dns_query()),
    (6, "setup_reply_response", dns_a_response()),
    (7, "bogus_wild", b"wildcard.example.com\x00".ljust(1025, b"\x00") + dns_a_response()),
    (8, "ignored_a", dns_a_response()),
    (8, "ignored_aaaa", dns_aaaa_response()),
    (8, "ignored_long", dns_long_name()),
]
for sel, name, payload in RFC1035:
    write_seed(f"fuzz_rfc1035/{name}", sel, payload)

# ============================================================================
# fuzz_auth — answer_auth, exercise zone transfer + queries
# ============================================================================
AUTH = [
    (0, "axfr", b"\x00" * 4 + dns_axfr()),
    (0, "soa_query", b"\x00" * 4 + dns_query(b"auth.example.com", qtype=6)),
    (0, "ns_query", b"\x00" * 4 + dns_query(b"auth.example.com", qtype=2)),
    (0, "any_query", b"\x00" * 4 + dns_query(b"auth.example.com", qtype=255)),
    (0, "a_query", b"\x00" * 4 + dns_query(b"host.auth.example.com", qtype=1)),
    (0, "aaaa_query", b"\x00" * 4 + dns_query(b"host.auth.example.com", qtype=28)),
    (1, "txt_query", b"\x00" * 4 + dns_query(b"auth.example.com", qtype=16)),
    (1, "ixfr", b"\x00" * 4 + dns_query(b"auth.example.com", qtype=251)),
    (1, "wildcard_query", b"\x00" * 4 + dns_query(b"unknown.auth.example.com")),
]
for sel, name, payload in AUTH:
    write_seed(f"fuzz_auth/{name}", sel, payload)

# ============================================================================
# fuzz_dhcp — DHCPv4 packet variants
# ============================================================================
DHCP = [
    (0, "discover", dhcp_packet(msgtype=1)),
    (1, "offer", dhcp_packet(msgtype=2)),
    (1, "request", dhcp_packet(msgtype=3)),
    (1, "decline", dhcp_packet(msgtype=4)),
    (1, "ack", dhcp_packet(msgtype=5)),
    (1, "nak", dhcp_packet(msgtype=6)),
    (1, "release", dhcp_release()),
    (1, "inform", dhcp_inform()),
    (0, "with_relay_agent", dhcp_with_relay_agent()),
    (0, "with_fqdn", dhcp_with_client_fqdn()),
    (0, "discover_no_hostname", dhcp_packet(hostname=b"", vendor=b"")),
    (0, "discover_long_hostname", dhcp_packet(hostname=b"x" * 32)),
]
for sel, name, payload in DHCP:
    write_seed(f"fuzz_dhcp/{name}", sel, payload)

# ============================================================================
# fuzz_dhcp6 — DHCPv6 message variants
# ============================================================================
DHCP6 = [
    (0, "solicit", dhcp6_msg(1)),
    (1, "advertise", dhcp6_msg(2)),
    (1, "request", dhcp6_msg(3)),
    (1, "renew", dhcp6_msg(5)),
    (1, "rebind", dhcp6_msg(6)),
    (1, "release", dhcp6_msg(8)),
    (1, "decline", dhcp6_msg(9)),
    (1, "information_request", dhcp6_msg(11)),
    (0, "relay_forw", dhcp6_relay_forw()),
]
for sel, name, payload in DHCP6:
    write_seed(f"fuzz_dhcp6/{name}", sel, payload)

# ============================================================================
# fuzz_util — short hostname pairs (FuzzedDataProvider, no preamble needed)
# ============================================================================
UTIL = [
    (b"example.com", b"EXAMPLE.com"),
    (b"*.example.com", b"foo.example.com"),
    (b"00:11:22:33:44:55", b""),
    (b"sub.example.com", b"example.com"),
    (b"a.b.c.d.e.f.g.example.com", b"example.com"),
    (b"xn--fsq.com", b"xn--fsq.com"),
    (b"_sip._tcp.example.com", b"example.com"),
    (b"deadbeef-1234", b"de:ad:be:ef:12:34"),
]
for i, (a, b) in enumerate(UTIL):
    p = os.path.join(OUT, "fuzz_util", f"util_{i}.bin")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(a + b"\x00" + b + b"\x00" + b"\x00" * 64)

print("done", file=sys.stderr)

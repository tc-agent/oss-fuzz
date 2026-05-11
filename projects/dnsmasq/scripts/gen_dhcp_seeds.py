#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
"""Generate richer DHCP / DHCPv6 seeds for fuzz_dhcp and fuzz_dhcp6.

Includes one seed per DHCP option type so the libFuzzer mutator starts
with packets that exercise each option_find() branch in rfc2131.c, and
similarly per DHCPv6 option number for rfc3315.c.
"""
import os
import struct
import sys

OUT_DHCP = sys.argv[1] if len(sys.argv) > 1 else "."
OUT_DHCP6 = sys.argv[2] if len(sys.argv) > 2 else "."

# Reuse the filler from gen_seeds.py so init_daemon's preamble is satisfied.
sys.path.insert(0, os.path.dirname(__file__))
from gen_seeds import filler


def encode_opt(code, data):
    return bytes([code, len(data)]) + bytes(data)


def dhcp_packet(msgtype, options):
    """BOOTREQUEST with the magic cookie and a configurable option block."""
    p = bytearray(240)
    p[0] = 1
    p[1] = 1   # htype Ethernet
    p[2] = 6   # hlen
    p[3] = 0   # hops
    struct.pack_into(">I", p, 4, 0xDEADBEEF)
    struct.pack_into(">H", p, 10, 0x8000)
    p[28:34] = b"\x00\x11\x22\x33\x44\x55"
    p[236:240] = b"\x63\x82\x53\x63"
    opts = bytearray()
    opts += encode_opt(53, [msgtype])
    for code, data in options:
        opts += encode_opt(code, data)
    opts.append(255)
    return bytes(p) + bytes(opts)


# (label, msgtype, [extra options]). Option codes per RFC 2132.
DHCP_SEEDS = [
    ("discover_simple", 1, []),
    ("request_simple", 3, []),
    ("decline_simple", 4, []),
    ("ack_simple", 5, []),
    ("nak_simple", 6, []),
    ("release_simple", 7, []),
    ("inform_simple", 8, []),
    # client-id (option 61)
    ("with_clientid_mac", 3, [(61, [1, 0, 0x11, 0x22, 0x33, 0x44, 0x55])]),
    ("with_clientid_string", 3, [(61, [0] + list(b"client-id"))]),
    # hostname (option 12)
    ("with_hostname", 1, [(12, list(b"myhost"))]),
    ("with_hostname_long", 1, [(12, list(b"hostname-that-is-much-longer-than-typical"))]),
    # requested IP (50)
    ("requested_ip", 3, [(50, [192, 168, 1, 100])]),
    # server identifier (54)
    ("server_id", 3, [(54, [192, 168, 1, 1])]),
    # parameter request list (55)
    ("param_request", 1, [(55, [1, 3, 6, 15, 28, 51, 58, 59])]),
    # vendor-class (60)
    ("vendor_pxe", 1, [(60, list(b"PXEClient"))]),
    ("vendor_msft", 1, [(60, list(b"MSFT 5.0"))]),
    ("vendor_long", 1, [(60, list(b"a" * 64))]),
    # vendor-options (43)
    ("vendor_opts", 1, [(60, list(b"PXEClient")),
                       (43, [6, 1, 0x08, 9, 4, 1, 2, 3, 4])]),
    # user-class (77)
    ("user_class", 1, [(77, [4] + list(b"iPXE"))]),
    # client FQDN (81)
    ("client_fqdn", 1, [(81, [0x01, 0, 0] + list(b"client"))]),
    # relay agent info (82): circuit-id (1), remote-id (2), subscriber-id (6)
    ("relay_agent", 3, [(82, [1, 4, 0xAA, 0xBB, 0xCC, 0xDD,
                              2, 6, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6])]),
    ("relay_subscriber", 3, [(82, [6, 5] + list(b"sub01"))]),
    # subnet-select (118)
    ("subnet_select", 3, [(118, [10, 0, 0, 0])]),
    # arch type (93)
    ("arch_type", 1, [(93, [0, 0]),     # IA-32 BIOS
                      (94, [1, 0, 0]),  # NIC type
                      (97, [0] + list(b"clientuuid1234567"))]),  # UUID
    # boot file name override (67) + tftp server name (66)
    ("boot_file", 3, [(66, list(b"server.example.com")),
                     (67, list(b"pxelinux.0"))]),
    # rapid-commit (80)
    ("rapid_commit", 1, [(80, [])]),
    # auto-config (116) — magic cookie / option 60 / boot path combos
    ("auto_config", 1, [(116, [1])]),
    # giaddr-relayed
    ("relayed", 3, []),  # Set giaddr below
    # malformed: option with bogus length
    ("malformed_short", 1, [(12, [])]),
    ("malformed_long", 1, [(82, [1] * 200)]),
    # truncated packet (less than 240 fixed header) — exercise size checks
]
os.makedirs(OUT_DHCP, exist_ok=True)
for i, (label, mt, opts) in enumerate(DHCP_SEEDS):
    pkt = dhcp_packet(mt, opts)
    if label == "relayed":
        pkt = bytearray(pkt)
        pkt[24:28] = b"\x0a\x00\x00\x01"  # giaddr
        pkt = bytes(pkt)
    # selector byte (mod 2 in fuzz_dhcp), then preamble, then packet
    data = bytes([i & 1]) + filler() + pkt
    with open(os.path.join(OUT_DHCP, f"{i:03d}_{label}"), "wb") as f:
        f.write(data)
print(f"wrote {len(DHCP_SEEDS)} DHCP seeds", file=sys.stderr)


def dhcp6_msg(msgtype, options):
    msg = bytearray()
    msg += bytes([msgtype, 0xAB, 0xCD, 0xEF])
    for code, data in options:
        msg += struct.pack(">HH", code, len(data)) + bytes(data)
    return bytes(msg)


# DHCPv6 messages — vary type and options.
DHCP6_SEEDS = [
    # SOLICIT (1)
    ("solicit_minimal", 1, [(8, [0, 0])]),  # elapsed-time only
    ("solicit_with_id", 1, [(1, [0, 3, 0, 1] + [0, 0x11, 0x22, 0x33, 0x44, 0x55]),
                            (3, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),  # IA_NA
                            (8, [0, 0])]),
    ("solicit_oro", 1, [(1, [0, 3, 0, 1] + [0, 0x11, 0x22, 0x33, 0x44, 0x55]),
                        (6, [0, 23, 0, 24, 0, 56])]),  # ORO: DNS, DOMAIN, NTP
    ("solicit_rapid", 1, [(1, [0, 3, 0, 1] + [0, 0x11, 0x22, 0x33, 0x44, 0x55]),
                          (14, [])]),  # RAPID_COMMIT
    ("solicit_iata", 1, [(4, [0, 0, 0, 1])]),  # IA_TA
    ("solicit_iapd", 1, [(25, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])]),  # IA_PD
    ("solicit_user_class", 1, [(15, [0, 4] + list(b"iPXE"))]),  # user-class
    ("solicit_vendor_class", 1, [(16, [0, 0, 0, 0xAA, 0, 4] + list(b"PXE6"))]),  # vendor-class
    ("solicit_fqdn", 1, [(39, [1, 6] + list(b"\x06client"))]),  # FQDN
    # REQUEST (3)
    ("request", 3, [(1, [0, 3, 0, 1] + [0, 0x11, 0x22, 0x33, 0x44, 0x55]),
                    (2, [0, 1, 0, 0xa, 0, 1] + [0] * 8),  # SERVER_ID
                    (3, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])]),
    # CONFIRM (4) / RENEW (5) / REBIND (6)
    ("confirm", 4, [(1, [0, 3, 0, 1] + [0] * 6),
                    (3, [0, 0, 0, 1] + [0] * 8)]),
    ("renew", 5, [(1, [0, 3, 0, 1] + [0] * 6),
                  (2, [0, 1, 0, 0xa] + [0] * 10)]),
    ("rebind", 6, [(1, [0, 3, 0, 1] + [0] * 6),
                   (3, [0, 0, 0, 1] + [0] * 8)]),
    # RELEASE (8) / DECLINE (9)
    ("release", 8, [(1, [0, 3, 0, 1] + [0] * 6),
                    (2, [0, 1, 0, 0xa] + [0] * 10),
                    (3, [0, 0, 0, 1] + [0] * 8)]),
    ("decline", 9, [(1, [0, 3, 0, 1] + [0] * 6),
                    (3, [0, 0, 0, 1] + [0] * 8)]),
    # INFORMATION-REQUEST (11)
    ("info_request", 11, [(1, [0, 3, 0, 1] + [0] * 6),
                          (6, [0, 23, 0, 24])]),
    # RELAY-FORW (12) wrapping a SOLICIT
    ("relay_forw", 12,
     [(9, struct.pack(">BBB", 1, 0xAB, 0xCD) + b"\xEF")]),  # OPTION_RELAY_MSG (truncated)
    # malformed
    ("oversize_option", 1, [(1, [0xFF] * 200)]),
    ("zero_option", 1, [(1, [])]),
]
os.makedirs(OUT_DHCP6, exist_ok=True)
for i, (label, mt, opts) in enumerate(DHCP6_SEEDS):
    pkt = dhcp6_msg(mt, opts)
    data = bytes([i & 1]) + filler() + pkt
    with open(os.path.join(OUT_DHCP6, f"{i:03d}_{label}"), "wb") as f:
        f.write(data)
print(f"wrote {len(DHCP6_SEEDS)} DHCPv6 seeds", file=sys.stderr)

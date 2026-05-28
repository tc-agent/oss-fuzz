#!/usr/bin/env python3
# Copyright 2026 Google Inc.
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
#
################################################################################
"""Generate fuzzing seed inputs for hostap in-tree fuzz harnesses.

Run as:  gen_seeds.py <fuzzing_dir>

For each harness directory under <fuzzing_dir> that this script knows about,
extra seed files are written into <harness>/corpus/ alongside the small
example corpus already shipped upstream. Existing files are never removed.

Every seed here is produced from readable, structured code (no opaque binary
blobs are checked in): protocol frames are assembled field-by-field from the
relevant RFC / IEEE 802.11 / hostap wire formats so a reviewer can audit
exactly what each byte means.
"""
import os
import struct
import sys


def w(corpus_dir, name, data):
    os.makedirs(corpus_dir, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    with open(os.path.join(corpus_dir, name), "wb") as f:
        f.write(data)


# ---------------------------------------------------------------------------
# json  (src/utils/json.c parser, as used by DPP)
# ---------------------------------------------------------------------------
JSON_SEEDS = {
    "g-nested": '{"name":"v","arr":[1,2,3,{"k":"v"}],"obj":{"a":{"b":{"c":'
                '[true,false,null]}}},"num":-12.5e3,"empty":{},"earr":[]}',
    "g-escapes": '{"esc":"a\\nb\\tc\\\\d\\"e\\/f\\b\\f\\r","uni":'
                 '"\\u00e9\\u20ac\\ud834\\udd1e","empty":""}',
    "g-numbers": '[0,-0,1,-1,3.14,-2.7,1e10,1E-10,1.5e+3,'
                 '123456789012345,0.000001]',
    "g-deep": '[[[[[[[[[[{"x":[[[[1]]]]}]]]]]]]]]]',
    "g-dpp-conf": '{"wi-fi_tech":"infra","discovery":{"ssid":"net"},'
                  '"cred":{"akm":"psk","pass":"secret-password"}}',
    "g-dpp-jws": '{"typ":"dppCon","kid":"kMcegDBPmNZVakAsBZOzOoCsv'
                 'Qjkr_nEAp9uF-EDmVE","alg":"ES256"}',
    "g-bools": '{"t":true,"f":false,"n":null,"mix":[true,null,false,'
               '{"q":null}]}',
    "g-scalar-str": '"top level string"',
    "g-scalar-true": 'true',
    "g-scalar-num": '-1234.5678e9',
    "g-whitespace": '{\n  "a" :  [ 1 , 2 , { "d" : "ok" } ] ,\n'
                    '  "b"\t:\t"v"\n}',
    "g-dpp-enrollee": '{"name":"E","mud_url":"https://ex.com/mud",'
                      '"netRole":"sta","cred":{"akm":"dpp",'
                      '"signedConnector":"eyJ0eXAi"}}',
    "g-edge": '{"a":-0.0,"b":1e0,"c":[],"d":{},"e":"","f":" "}',
    "g-mixed-deep": '{"l1":{"l2":{"l3":{"l4":{"l5":{"arr":'
                    '[{"o":1},{"o":2},{"o":[null,true]}]}}}}}}',
    "g-array-top": '[{"k":1},{"k":2},"s",3,true,null,[1,[2,[3]]]]',
    "g-unbalanced": '{"a":[1,2,3}',
    "g-trailing": '{"a":1,}',
    "g-bare-word": 'undefined',
    "g-bignum": '999999999999999999999999999999999999999999999',
    "g-empty": '',
}


def gen_json(fz):
    cd = os.path.join(fz, "json", "corpus")
    for k, v in JSON_SEEDS.items():
        w(cd, k, v)


# ---------------------------------------------------------------------------
# dpp-uri  (src/common/dpp.c dpp_parse_uri)
# ---------------------------------------------------------------------------
# A realistic compressed P-256 SubjectPublicKeyInfo, base64 (from hostap docs).
DPP_K = ("MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADM2boj9hWXVqAYL/"
         "AHHsenjzwjf9HwEsfksjEScdSPyo=")
DPP_SEEDS = {
    "g-full": "DPP:C:81/1,115/36;M:010203040506;I:id;V:2;K:%s;" % DPP_K,
    "g-min": "DPP:K:%s;" % DPP_K,
    "g-chan": "DPP:C:81/1;K:%s;" % DPP_K,
    "g-mac": "DPP:M:aabbccddeeff;K:%s;" % DPP_K,
    "g-info": "DPP:I:Sample-Info-String;K:%s;" % DPP_K,
    "g-host": "DPP:H:example.com:8908;K:%s;" % DPP_K,
    "g-ver": "DPP:V:3;K:%s;" % DPP_K,
    "g-multi": "DPP:C:81/1;C:115/36;M:010203040506;I:x;V:2;K:%s;" % DPP_K,
    "g-bad-nokey": "DPP:C:81/1;M:010203040506;",
    "g-bad-prefix": "WXY:K:%s;" % DPP_K,
    "g-bad-b64": "DPP:K:@@@not-base64@@@;",
    "g-empty": "DPP:;",
}


def gen_dpp(fz):
    cd = os.path.join(fz, "dpp-uri", "corpus")
    for k, v in DPP_SEEDS.items():
        w(cd, k, v)


# ---------------------------------------------------------------------------
# RADIUS  (src/radius/radius.c radius_msg_parse + accessors)
# ---------------------------------------------------------------------------
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCESS_CHALLENGE = 11
RADIUS_ACCOUNTING_REQUEST = 4


def _attr(t, v):
    if isinstance(v, str):
        v = v.encode()
    return bytes([t, len(v) + 2]) + v


def _radius(code, ident, attrs, authenticator=None):
    if authenticator is None:
        authenticator = bytes(range(16))
    body = b"".join(attrs)
    length = 20 + len(body)
    return bytes([code, ident]) + struct.pack(">H", length) + \
        authenticator + body


def _vsa(vendor_id, vtype, vval):
    if isinstance(vval, str):
        vval = vval.encode()
    inner = bytes([vtype, len(vval) + 2]) + vval
    return _attr(26, struct.pack(">I", vendor_id) + inner)


def gen_radius(fz):
    cd = os.path.join(fz, "radius", "corpus")
    MS_VENDOR = 311

    # 1) Access-Request with User-Name, NAS-IP, NAS-Port, Message-Auth
    a = [
        _attr(1, "user@example.com"),          # User-Name
        _attr(4, bytes([192, 0, 2, 1])),       # NAS-IP-Address
        _attr(5, struct.pack(">I", 7)),        # NAS-Port
        _attr(32, "nas-id"),                   # NAS-Identifier
        _attr(80, bytes(16)),                  # Message-Authenticator
    ]
    w(cd, "g-access-request", _radius(RADIUS_ACCESS_REQUEST, 1, a))

    # 2) Access-Challenge with State + fragmented EAP-Message
    eap = bytes([1, 7, 0, 16, 1]) + b"identity"  # EAP request/identity-ish
    a = [
        _attr(24, b"state-cookie-0123"),       # State
        _attr(79, eap),                        # EAP-Message
        _attr(79, b"\x01\x08\x00\x06\x03\x04"),  # 2nd EAP-Message fragment
        _attr(80, bytes(16)),                  # Message-Authenticator
    ]
    w(cd, "g-access-challenge", _radius(RADIUS_ACCESS_CHALLENGE, 2, a))

    # 3) Access-Accept with VLAN tunnel attrs + MS-MPPE keys (VSA)
    a = [
        _attr(64, b"\x00\x00\x00\x0d"),        # Tunnel-Type = VLAN (tag 0)
        _attr(65, b"\x00\x00\x00\x06"),        # Tunnel-Medium-Type = 802
        _attr(81, b"\x00" + b"123"),           # Tunnel-Private-Group-Id
        _attr(64, b"\x01\x00\x00\x0d"),        # tagged Tunnel-Type
        _attr(81, b"\x01" + b"456"),           # tagged group id
        _vsa(MS_VENDOR, 16, b"\x00" + bytes(34)),  # MS-MPPE-Send-Key
        _vsa(MS_VENDOR, 17, b"\x00" + bytes(34)),  # MS-MPPE-Recv-Key
        _attr(26, struct.pack(">I", MS_VENDOR) + bytes([1, 4, 0, 1])),
    ]
    w(cd, "g-access-accept-vlan", _radius(RADIUS_ACCESS_ACCEPT, 3, a))

    # 4) Access-Accept with Tunnel-Password (salted) + Class
    salt = b"\x80\x01"
    a = [
        _attr(69, b"\x00" + salt + bytes(16)),  # Tunnel-Password
        _attr(25, b"class-attribute-data"),     # Class
        _attr(27, struct.pack(">I", 3600)),     # Session-Timeout
        _attr(85, struct.pack(">I", 600)),      # Acct-Interim-Interval
    ]
    w(cd, "g-access-accept-tunnelpw", _radius(RADIUS_ACCESS_ACCEPT, 4, a))

    # 5) Access-Reject + Reply-Message
    a = [_attr(18, "Authentication failed"), _attr(79, bytes([4, 4, 0, 4]))]
    w(cd, "g-access-reject", _radius(RADIUS_ACCESS_REJECT, 5, a))

    # 6) Accounting-Request with many stat attrs
    a = [
        _attr(40, struct.pack(">I", 1)),       # Acct-Status-Type = Start
        _attr(44, "session-001"),              # Acct-Session-Id
        _attr(42, struct.pack(">I", 12345)),   # Acct-Input-Octets
        _attr(43, struct.pack(">I", 54321)),   # Acct-Output-Octets
        _attr(8, bytes([10, 0, 0, 5])),        # Framed-IP-Address
    ]
    w(cd, "g-accounting", _radius(RADIUS_ACCOUNTING_REQUEST, 6, a))

    # 7) Long EAP spread over many EAP-Message attrs (reassembly path)
    big = bytes([1, 7]) + struct.pack(">H", 4 + 600) + bytes(600)
    frags = [big[i:i + 253] for i in range(0, len(big), 253)]
    a = [_attr(79, fr) for fr in frags] + [_attr(80, bytes(16))]
    w(cd, "g-eap-reassembly", _radius(RADIUS_ACCESS_CHALLENGE, 7, a))

    # 8) Malformed: attribute length overruns buffer
    w(cd, "g-bad-attrlen",
      _radius(RADIUS_ACCESS_REQUEST, 8, [bytes([1, 200]) + b"short"]))

    # 9) Zero-length attribute / truncated header
    w(cd, "g-bad-zeroattr", bytes([RADIUS_ACCESS_REQUEST, 9, 0, 22]) +
      bytes(16) + bytes([1, 2]))


# ---------------------------------------------------------------------------
# SAE commit  (src/common/sae.c sae_parse_commit), group 19 (P-256)
# ---------------------------------------------------------------------------
WLAN_EID_EXTENSION = 255
WLAN_EID_EXT_REJECTED_GROUPS = 92
WLAN_EID_EXT_ANTI_CLOGGING_TOKEN = 93
WLAN_EID_EXT_PASSWORD_IDENTIFIER = 33


def gen_sae(fz):
    cd = os.path.join(fz, "sae", "corpus")
    PL = 32  # P-256 prime length
    # Reuse a known on-curve element if upstream provided one; otherwise the
    # parser still walks all length / IE / token branches before the crypto
    # point check, so structural variety is what matters here.
    tmpl = os.path.join(cd, "sae-commit-valid.dat")
    base = None
    if os.path.exists(tmpl):
        with open(tmpl, "rb") as f:
            base = f.read()
    if not base or len(base) < 2 + 3 * PL:
        base = struct.pack("<H", 19) + bytes(3 * PL)
    grp = base[:2]
    scalar = base[2:2 + PL]
    element = base[2 + PL:2 + 3 * PL]
    commit = grp + scalar + element

    def ext_ie(ext_id, payload):
        body = bytes([ext_id]) + payload
        return bytes([WLAN_EID_EXTENSION, len(body)]) + body

    w(cd, "g-plain", commit)
    # Group variants (supported, unsupported, FFC, sentinel)
    for g in (19, 20, 21, 25, 26, 1, 2, 5, 0, 0xffff):
        w(cd, "g-group-%d" % g, struct.pack("<H", g) + scalar + element)
    # With anti-clogging token (raw, non-h2e form)
    w(cd, "g-token", commit + b"\xaa" * 32)
    w(cd, "g-token-long", commit + b"\xbb" * 80)
    # H2E token container element
    w(cd, "g-h2e-token",
      commit + ext_ie(WLAN_EID_EXT_ANTI_CLOGGING_TOKEN, b"\x01" + b"\xcc" * 31))
    # Password identifier element
    w(cd, "g-pw-id",
      commit + ext_ie(WLAN_EID_EXT_PASSWORD_IDENTIFIER, b"ident"))
    # Rejected groups element
    w(cd, "g-rej-groups",
      commit + ext_ie(WLAN_EID_EXT_REJECTED_GROUPS,
                       struct.pack("<HH", 20, 21)))
    # Combined trailing IEs
    w(cd, "g-combo",
      commit +
      ext_ie(WLAN_EID_EXT_PASSWORD_IDENTIFIER, b"pw") +
      ext_ie(WLAN_EID_EXT_REJECTED_GROUPS, struct.pack("<H", 20)))
    # Truncated / short
    w(cd, "g-short-scalar", grp + scalar[:10])
    w(cd, "g-only-group", grp)
    w(cd, "g-empty", b"")


# ---------------------------------------------------------------------------
# EAP peer fuzzers (eap-sim-peer / eap-aka-peer / eap-mschapv2-peer)
# Wire format consumed by the harness: repeated [u16 BE len][EAP packet].
# ---------------------------------------------------------------------------
EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_SIM = 18
EAP_TYPE_AKA = 23
EAP_TYPE_MSCHAPV2 = 26


def _eap_req(ident, etype, payload=b""):
    body = bytes([etype]) + payload
    pkt = bytes([1, ident]) + struct.pack(">H", 4 + len(body)) + body
    return pkt


def _framed(*pkts):
    out = b""
    for p in pkts:
        out += struct.pack(">H", len(p)) + p
    return out


def _eap_sim_attr(atype, payload):
    # EAP-SIM/AKA attribute: type(1) len-in-4byte-units(1) value
    val = bytes([atype, (len(payload) + 2 + 3) // 4]) + payload
    pad = (-len(val)) % 4
    return val + bytes(pad)


def gen_eap_sim(fz):
    cd = os.path.join(fz, "eap-sim-peer", "corpus")
    # SIM subtypes: Start=10, Challenge=11, Notification=12, Re-auth=13
    start = bytes([10, 0, 0]) + \
        _eap_sim_attr(15, b"\x00\x02\x01\x00\x01\x00")  # AT_VERSION_LIST
    challenge = bytes([11, 0, 0]) + \
        _eap_sim_attr(1, bytes(2) + bytes(16)) + \
        _eap_sim_attr(11, bytes(2) + bytes(16))         # AT_RAND + AT_MAC
    notif = bytes([12, 0, 0]) + _eap_sim_attr(12, b"\x00\x00")
    w(cd, "g-id-start",
      _framed(_eap_req(1, EAP_TYPE_IDENTITY),
              _eap_req(2, EAP_TYPE_SIM, start),
              _eap_req(3, EAP_TYPE_SIM, challenge)))
    w(cd, "g-notification",
      _framed(_eap_req(1, EAP_TYPE_SIM, notif)))
    w(cd, "g-start-only", _framed(_eap_req(5, EAP_TYPE_SIM, start)))
    w(cd, "g-truncated", _framed(_eap_req(1, EAP_TYPE_SIM, b"\x0b")))
    w(cd, "g-empty", b"")


def gen_eap_aka(fz):
    cd = os.path.join(fz, "eap-aka-peer", "corpus")
    # AKA subtypes: Challenge=1, Authentication-Reject=2, Identity=5,
    # Notification=12
    ident = bytes([5, 0, 0]) + _eap_sim_attr(13, b"\x00\x05hello")
    challenge = bytes([1, 0, 0]) + \
        _eap_sim_attr(1, bytes(2) + bytes(16)) + \
        _eap_sim_attr(2, bytes(2) + bytes(16)) + \
        _eap_sim_attr(11, bytes(2) + bytes(16))
    w(cd, "g-id-challenge",
      _framed(_eap_req(1, EAP_TYPE_IDENTITY),
              _eap_req(2, EAP_TYPE_AKA, ident),
              _eap_req(3, EAP_TYPE_AKA, challenge)))
    w(cd, "g-challenge-only",
      _framed(_eap_req(7, EAP_TYPE_AKA, challenge)))
    w(cd, "g-notif",
      _framed(_eap_req(1, EAP_TYPE_AKA, bytes([12, 0, 0]))))
    w(cd, "g-empty", b"")


def gen_eap_mschapv2(fz):
    cd = os.path.join(fz, "eap-mschapv2-peer", "corpus")
    # MSCHAPv2 opcodes: Challenge=1, Success=3, Failure=4
    chal = bytes([1, 1]) + struct.pack(">H", 5 + 16 + 8) + \
        bytes(16) + b"AuthSrv8"
    succ = bytes([3, 2]) + struct.pack(">H", 4 + 42) + \
        b"S=" + b"0" * 40
    fail = bytes([4, 3]) + struct.pack(">H", 4 + 45) + \
        b"E=691 R=1 C=" + b"0" * 32 + b" V=3"
    w(cd, "g-challenge",
      _framed(_eap_req(1, EAP_TYPE_IDENTITY),
              _eap_req(2, EAP_TYPE_MSCHAPV2, chal)))
    w(cd, "g-success",
      _framed(_eap_req(3, EAP_TYPE_MSCHAPV2, succ)))
    w(cd, "g-failure",
      _framed(_eap_req(4, EAP_TYPE_MSCHAPV2, fail)))
    w(cd, "g-empty", b"")


# ---------------------------------------------------------------------------
# eapol-supp  (src/eapol_supp + rsn_supp): EAPOL frame fed directly.
# ---------------------------------------------------------------------------
def gen_eapol_supp(fz):
    cd = os.path.join(fz, "eapol-supp", "corpus")

    def eapol(ptype, payload):
        return bytes([2, ptype]) + struct.pack(">H", len(payload)) + payload

    # EAPOL-EAP carrying an EAP Request/Identity
    eap_id = bytes([1, 1, 0, 5, EAP_TYPE_IDENTITY])
    w(cd, "g-eap-identity", eapol(0, eap_id))
    # EAPOL-EAP carrying EAP Request/Notification
    eap_notif = bytes([1, 2, 0, 7, EAP_TYPE_NOTIFICATION]) + b"hi"
    w(cd, "g-eap-notif", eapol(0, eap_notif))
    # EAPOL-Start / EAPOL-Logoff
    w(cd, "g-start", eapol(1, b""))
    w(cd, "g-logoff", eapol(2, b""))
    # EAPOL-Key (RSN, 4-way msg1-ish): key descriptor type 2 + info + body
    key = bytes([2]) + struct.pack(">H", 0x008a) + struct.pack(">H", 16)
    key += struct.pack(">Q", 1) + bytes(32)          # replay counter + nonce
    key += bytes(16) + bytes(8) + bytes(8)           # IV + RSC + reserved
    key += bytes(16) + struct.pack(">H", 0)          # MIC + key data len
    w(cd, "g-eapol-key-m1", eapol(3, key))
    w(cd, "g-truncated", eapol(0, b"\x01"))
    w(cd, "g-empty", b"")


# ---------------------------------------------------------------------------
# p2p / wnm : append synthetic IE/attribute permutations to existing real
# frames so the TLV-walking parsers see more element-ID/length combinations.
# ---------------------------------------------------------------------------
def _existing(cd):
    out = []
    if os.path.isdir(cd):
        for fn in sorted(os.listdir(cd)):
            p = os.path.join(cd, fn)
            if os.path.isfile(p) and not fn.startswith("g-"):
                with open(p, "rb") as f:
                    out.append((fn, f.read()))
    return out


def gen_p2p(fz):
    cd = os.path.join(fz, "p2p", "corpus")
    base = _existing(cd)
    # P2P IE = vendor-specific (0xDD) + WFA OUI 50 6F 9A + type 09 + attrs.
    def p2p_attr(aid, body):
        return bytes([aid]) + struct.pack("<H", len(body)) + body
    attrs = b""
    attrs += p2p_attr(2, b"\x00\x00")                       # Capability
    attrs += p2p_attr(3, bytes(6))                          # Device ID
    attrs += p2p_attr(13, bytes(6) + bytes(2) + bytes(8))   # Device Info
    attrs += p2p_attr(0, b"\x00")                            # Status
    ie = bytes([0xDD, 4 + len(attrs)]) + b"\x50\x6f\x9a\x09" + attrs
    if base:
        fn, b = base[0]
        w(cd, "g-augmented", b + ie)
    w(cd, "g-ie-only", ie)
    w(cd, "g-double-ie", ie + ie)


def gen_wnm(fz):
    cd = os.path.join(fz, "wnm", "corpus")
    base = _existing(cd)
    if not base:
        return
    fn, b = base[0]
    # Append extra information elements (id, len, value) after a real frame.
    extra = b""
    for eid, val in ((0, b"ssid"), (7, b"\x00\x00"), (37, b"\x01\x02\x03"),
                     (255, b"\x5b\x01")):
        extra += bytes([eid, len(val)]) + val
    w(cd, "g-extra-ies", b + extra)
    w(cd, "g-truncated", b[:max(1, len(b) // 2)])


# ---------------------------------------------------------------------------
# ap-mgmt : IEEE 802.11 management frames fed to a live hostapd via
# ieee802_11_mgmt(). Wire format consumed by the harness is a concatenation
# of [u16 BE frame-length][frame]. The harness AP uses own/BSSID
# 02:00:00:00:03:00, SSID "test", 2.4 GHz ch 1, and pre-adds an associated
# STA 02:00:00:00:00:00. Frames are assembled field-by-field from the
# 802.11 MAC header + per-subtype body so every byte is auditable.
# ---------------------------------------------------------------------------
AP = bytes.fromhex("020000000300")          # AP own addr / BSSID
STA0 = bytes.fromhex("020000000000")        # pre-associated STA
STA1 = bytes.fromhex("020000000001")        # fresh STA
BCAST = b"\xff" * 6


def _ie(eid, val):
    return bytes([eid, len(val)]) + val


# Minimal but well-formed IEs reused across association/probe frames.
IE_SSID = _ie(0, b"test")
IE_RATES = _ie(1, bytes([0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]))
IE_EXTRATES = _ie(50, bytes([0x0c, 0x12, 0x18, 0x60]))
IE_DS = _ie(3, b"\x01")
IE_PWRCAP = _ie(33, b"\x00\x14")
IE_SUPPCH = _ie(36, b"\x01\x0b")
IE_HTCAP = _ie(45, bytes(26))
IE_EXTCAP = _ie(127, bytes(8))
IE_RM = _ie(70, bytes(5))
# RSN IE: v1, group CCMP, 1 pairwise CCMP, 1 AKM, caps 0
_OUI = bytes([0x00, 0x0f, 0xac])
def _rsn(akm):
    return _ie(48, struct.pack("<H", 1) + _OUI + bytes([4]) +
               struct.pack("<H", 1) + _OUI + bytes([4]) +
               struct.pack("<H", 1) + _OUI + bytes([akm]) +
               struct.pack("<H", 0))
IE_RSN = _rsn(2)        # PSK
IE_RSN_SAE = _rsn(8)    # SAE
IE_MDE = _ie(54, b"\xaa\xbb\x01")           # Mobility Domain (FT)


def _mgmt(subtype, da, sa, bssid, body, fc1=0x00):
    fc0 = (subtype << 4) | (0 << 2)         # type 0 = management
    hdr = bytes([fc0, fc1]) + b"\x00\x00" + da + sa + bssid + b"\x00\x00"
    return hdr + body


def _seq(*frames):
    out = b""
    for fr in frames:
        out += struct.pack(">H", len(fr)) + fr
    return out


def gen_ap_mgmt(fz):
    cd = os.path.join(fz, "ap-mgmt", "corpus")

    probe = _mgmt(4, BCAST, STA1, BCAST,
                  _ie(0, b"") + IE_RATES + IE_DS + IE_EXTCAP)
    auth_open1 = _mgmt(11, AP, STA1, AP,
                       struct.pack("<HHH", 0, 1, 0))          # Open seq1
    auth_open2 = _mgmt(11, AP, STA1, AP,
                       struct.pack("<HHH", 0, 2, 0))          # Open seq2
    auth_sae1 = _mgmt(11, AP, STA1, AP,
                      struct.pack("<HHH", 3, 1, 0) +
                      struct.pack("<H", 19) + bytes(32) + bytes(64))
    auth_sae2 = _mgmt(11, AP, STA1, AP,
                      struct.pack("<HHH", 3, 2, 0) +
                      struct.pack("<H", 0) + bytes(32))
    auth_ft = _mgmt(11, AP, STA1, AP, struct.pack("<HHH", 2, 1, 0))
    cap_li = struct.pack("<HH", 0x0431, 5)
    assoc = _mgmt(0, AP, STA1, AP,
                  cap_li + IE_SSID + IE_RATES + IE_EXTRATES + IE_PWRCAP +
                  IE_SUPPCH + IE_HTCAP + IE_RM + IE_RSN + IE_EXTCAP)
    assoc_sae = _mgmt(0, AP, STA1, AP,
                      cap_li + IE_SSID + IE_RATES + IE_RSN_SAE + IE_HTCAP +
                      IE_EXTCAP)
    reassoc = _mgmt(2, AP, STA1, AP,
                    cap_li + AP + IE_SSID + IE_RATES + IE_RSN + IE_MDE +
                    IE_EXTCAP)
    disassoc = _mgmt(10, AP, STA0, AP, struct.pack("<H", 8))
    deauth = _mgmt(12, AP, STA0, AP, struct.pack("<H", 3))

    def action(cat, body, sa=STA0):
        return _mgmt(13, AP, sa, AP, bytes([cat]) + body)

    act_saquery_req = action(8, b"\x00" + b"\x12\x34")
    act_saquery_resp = action(8, b"\x01" + b"\x12\x34")
    act_wnm_btm_query = action(10, b"\x06\x01\x00")
    act_wnm_btm_resp = action(10, b"\x08\x01\x00\x00\x00")
    act_wnm_notif = action(10, b"\x00\x01")
    act_rm_meas_req = action(5, b"\x00\x01\x00\x05" + _ie(0, bytes(14)))
    act_rm_link_req = action(5, b"\x02\x01\x00\x00")
    act_rm_neigh_req = action(5, b"\x04\x01")
    act_public_gas = action(4, b"\x0a\x00" + _ie(108, b"\x00") +
                            struct.pack("<H", 0))
    act_public_dpp = action(4, b"\x09\x50\x6f\x9a\x1a\x01\x00")
    act_ht = action(7, b"\x00\x00")
    act_vht = action(21, b"\x00\x00\x00")
    act_ba_addba = action(3, b"\x00\x01\x00\x10\x00\x00\x00")
    act_ba_delba = action(3, b"\x02\x00\x08\x25\x00")
    act_ft = action(6, b"\x01\x00" + AP + AP)
    act_vendor_wmm = action(17, b"\x50\xf2\x02\x00\x00")
    act_self_prot = action(9, b"\x01" + bytes(20))

    timing_adv = _mgmt(6, BCAST, STA1, AP, struct.pack("<HH", 0, 0))
    beacon = _mgmt(8, AP, AP, AP,
                   bytes(8) + struct.pack("<HH", 0x0431, 100) +
                   IE_SSID + IE_RATES + IE_DS)
    probe_resp = _mgmt(5, STA1, AP, AP,
                       bytes(8) + struct.pack("<HH", 0x0431, 100) +
                       IE_SSID + IE_RATES + IE_DS + IE_RSN)

    # One big sequence exercising the full association lifecycle + actions.
    w(cd, "g-assoc-lifecycle",
      _seq(probe, auth_open1, auth_open2, assoc, reassoc,
           act_saquery_req, act_saquery_resp, disassoc, deauth))
    w(cd, "g-sae-flow",
      _seq(probe, auth_sae1, auth_sae2, assoc_sae, deauth))
    w(cd, "g-action-mix",
      _seq(act_wnm_btm_query, act_wnm_btm_resp, act_wnm_notif,
           act_rm_meas_req, act_rm_link_req, act_rm_neigh_req,
           act_public_gas, act_public_dpp, act_ht, act_vht,
           act_ba_addba, act_ba_delba, act_ft, act_vendor_wmm,
           act_self_prot))
    w(cd, "g-ft-flow",
      _seq(probe, auth_ft, reassoc, act_ft))
    w(cd, "g-beacon-probe",
      _seq(beacon, probe, probe_resp, timing_adv))
    w(cd, "g-each-subtype",
      _seq(probe, auth_open1, assoc, reassoc, disassoc, deauth,
           act_saquery_req, beacon, probe_resp))
    # Truncated / malformed frames (header boundary handling).
    w(cd, "g-trunc-hdr", struct.pack(">H", 4) + b"\xb0\x00\x00\x00")
    w(cd, "g-zero-len", struct.pack(">H", 0))
    w(cd, "g-bad-flen", struct.pack(">H", 600) + b"\xb0\x00")


GENERATORS = [
    gen_json, gen_dpp, gen_radius, gen_sae,
    gen_eap_sim, gen_eap_aka, gen_eap_mschapv2,
    gen_eapol_supp, gen_p2p, gen_wnm, gen_ap_mgmt,
]


def main():
    fz = sys.argv[1] if len(sys.argv) > 1 else "."
    for g in GENERATORS:
        try:
            g(fz)
        except Exception as e:  # one bad harness must not block the rest
            sys.stderr.write("seed-gen %s failed: %s\n" % (g.__name__, e))
    print("seed generation done for", fz)


if __name__ == "__main__":
    main()

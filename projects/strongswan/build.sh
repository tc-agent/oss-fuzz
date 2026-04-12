#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

./autogen.sh

./configure CFLAGS="$CFLAGS -DNO_CHECK_MEMWIPE -DDEBUG_LEVEL=-1" \
	--enable-imc-test \
	--enable-tnccs-20 \
	--enable-libipsec \
	--enable-eap-radius \
	--enable-fuzzing \
	--with-libfuzzer=$LIB_FUZZING_ENGINE \
	--enable-monolithic \
	--disable-shared \
	--enable-static

make -j$(nproc)

fuzzers=$(find fuzz -maxdepth 1 -executable -type f -name 'fuzz_*')
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f $OUT/
	corpus=${fuzzer#fuzz_}
	if [ -d "fuzzing-corpora/${corpus}" ]; then
		zip -rj $OUT/${fuzzer}_seed_corpus.zip fuzzing-corpora/${corpus}
	fi
done

# Read the plugin lists that configure substituted into fuzz/Makefile, so
# our custom harnesses use the exact same PLUGINS strings as the upstream ones.
FD_PLUGINS=$(sed -n 's/^fd_plugins = //p' fuzz/Makefile)
FC_PLUGINS=$(sed -n 's/^fc_plugins = //p' fuzz/Makefile)

FUZZ_LDFLAGS="-lc++ -lstdc++"
FUZZ_INCS="-include $SRC/strongswan/config.h -I $SRC/strongswan/src/libstrongswan"

# Static crypto libs required by libstrongswan plugins
CRYPTO_LIBS="-Wl,-Bstatic -lcrypto -lgmp -Wl,-Bdynamic"

# -------------------------------------------------------------------------
# fuzz_ip_packet — exercises ip_packet_create() in libipsec.
# No plugins needed; ip_packet.c is pure struct parsing.
# -------------------------------------------------------------------------
if [ -f src/libipsec/.libs/libipsec.a ]; then
$CC $CFLAGS \
	$FUZZ_INCS \
	-I $SRC/strongswan/src/libipsec \
	$SRC/fuzz_ip_packet.c \
	src/libipsec/.libs/libipsec.a \
	src/libstrongswan/.libs/libstrongswan.a \
	$CRYPTO_LIBS \
	$LIB_FUZZING_ENGINE \
	$FUZZ_LDFLAGS \
	-o $OUT/fuzz_ip_packet

# Generate seed corpus: one minimal IPv4 packet and one minimal IPv6 packet.
python3 - <<'PYEOF'
import os, struct

out = os.environ['OUT']
seeds_dir = os.path.join(out, '_ip_packet_seeds')
os.makedirs(seeds_dir, exist_ok=True)

# Minimal IPv4 packet (20-byte header, no payload).
# Version=4, IHL=5, TOS=0, Total Length=20, TTL=64, Proto=TCP(6)
ipv4 = bytes([
    0x45, 0x00, 0x00, 0x14,   # ver/IHL, TOS, total_len=20
    0x00, 0x00, 0x00, 0x00,   # ID, flags+frag_offset
    0x40, 0x06, 0x00, 0x00,   # TTL=64, proto=TCP, checksum=0
    0x7f, 0x00, 0x00, 0x01,   # src 127.0.0.1
    0x7f, 0x00, 0x00, 0x01,   # dst 127.0.0.1
])
with open(os.path.join(seeds_dir, 'ipv4_minimal'), 'wb') as f:
    f.write(ipv4)

# Minimal IPv6 packet (40-byte header, no payload).
# Version=6, payload_len=0, next_header=59 (No Next Header), hop_limit=64
ipv6 = bytes([
    0x60, 0x00, 0x00, 0x00,   # ver=6, TC=0, flow=0
    0x00, 0x00, 0x3b, 0x40,   # payload_len=0, next=59(none), hop=64
]) + bytes(16) + bytes(16)    # src=::, dst=::
with open(os.path.join(seeds_dir, 'ipv6_minimal'), 'wb') as f:
    f.write(ipv6)

# IPv4 packet with a minimal TCP header (total = 20 + 20 = 40 bytes)
tcp_hdr = bytes([
    0x00, 0x50, 0x01, 0xbb,   # src_port=80, dst_port=443
    0x00, 0x00, 0x00, 0x01,   # seq=1
    0x00, 0x00, 0x00, 0x00,   # ack=0
    0x50, 0x00, 0xff, 0xff,   # data_offset=5, flags=0, window=65535
    0x00, 0x00, 0x00, 0x00,   # checksum=0, urg=0
])
ipv4_tcp = bytes([
    0x45, 0x00, 0x00, 0x28,   # total_len=40
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01,
    0x7f, 0x00, 0x00, 0x01,
]) + tcp_hdr
with open(os.path.join(seeds_dir, 'ipv4_tcp'), 'wb') as f:
    f.write(ipv4_tcp)

import zipfile
zip_path = os.path.join(out, 'fuzz_ip_packet_seed_corpus.zip')
with zipfile.ZipFile(zip_path, 'w') as zf:
    for name in os.listdir(seeds_dir):
        zf.write(os.path.join(seeds_dir, name), name)
PYEOF
else
	echo "WARNING: libipsec.a not found — skipping fuzz_ip_packet" >&2
fi

# -------------------------------------------------------------------------
# fuzz_tls_server_{def,cus} — exercises TLS server-side ClientHello parsing,
# extension parsing, and cipher suite selection (tls_server.c, tls_crypto.c).
# Two variants use different crypto back-ends (openssl vs gmp).
# -------------------------------------------------------------------------
TLS_INCS="$FUZZ_INCS -I $SRC/strongswan/src/libtls"

if [ -f src/libtls/.libs/libtls.a ]; then
$CC $CFLAGS \
	$TLS_INCS \
	-DPLUGINS="\"${FD_PLUGINS}\"" \
	$SRC/fuzz_tls_server.c \
	src/libtls/.libs/libtls.a \
	src/libstrongswan/.libs/libstrongswan.a \
	$CRYPTO_LIBS \
	$LIB_FUZZING_ENGINE \
	$FUZZ_LDFLAGS \
	-o $OUT/fuzz_tls_server_def

$CC $CFLAGS \
	$TLS_INCS \
	-DPLUGINS="\"${FC_PLUGINS}\"" \
	$SRC/fuzz_tls_server.c \
	src/libtls/.libs/libtls.a \
	src/libstrongswan/.libs/libstrongswan.a \
	$CRYPTO_LIBS \
	$LIB_FUZZING_ENGINE \
	$FUZZ_LDFLAGS \
	-o $OUT/fuzz_tls_server_cus

# Generate seed corpus for the TLS server harnesses: a valid TLS 1.2 and
# TLS 1.3 ClientHello record.  Both _def and _cus share the same corpus.
python3 - <<'PYEOF'
import os, struct, zipfile

out = os.environ['OUT']
seeds_dir = os.path.join(out, '_tls_server_seeds')
os.makedirs(seeds_dir, exist_ok=True)

def build_tls_record(content_type, version, payload):
    return bytes([content_type]) + struct.pack('>HH', version, len(payload)) + payload

def build_handshake(msg_type, body):
    # 1-byte type + 3-byte length
    return bytes([msg_type]) + struct.pack('>I', len(body))[1:] + body

def build_extensions(exts):
    data = b''.join(exts)
    return struct.pack('>H', len(data)) + data

def build_extension(ext_type, data):
    return struct.pack('>HH', ext_type, len(data)) + data

# ---- TLS 1.2 ClientHello ----
random32 = bytes(32)
session_id = b'\x00'              # length 0
# Cipher suites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) only
ciphers = struct.pack('>H', 2) + b'\x00\x2f'
compression = b'\x01\x00'         # length 1, null

# Extensions: renegotiation_info (empty, indicates initial handshake)
renego_ext = build_extension(0xff01, b'\x00')
exts = build_extensions([renego_ext])

hello12_body = (
    b'\x03\x03'     # legacy_version = TLS 1.2
    + random32
    + session_id
    + ciphers
    + compression
    + exts
)
hs12 = build_handshake(0x01, hello12_body)
rec12 = build_tls_record(0x16, 0x0301, hs12)   # record version = TLS 1.0
with open(os.path.join(seeds_dir, 'tls12_client_hello'), 'wb') as f:
    f.write(rec12)

# ---- TLS 1.3 ClientHello ----
# Requires: supported_versions ext (TLS 1.3), key_share ext, sig_algs ext
supported_versions_data = b'\x02\x03\x04'  # length 2, TLS 1.3
sig_algs_data = struct.pack('>H', 2) + b'\x04\x01'   # rsa_pkcs1_sha256

# key_share: x25519 (group 0x001d), 32-byte public key
x25519_key = bytes(32)
key_share_entry = struct.pack('>HH', 0x001d, 32) + x25519_key
key_share_data = struct.pack('>H', len(key_share_entry)) + key_share_entry

exts13 = build_extensions([
    build_extension(0x002b, supported_versions_data),  # supported_versions
    build_extension(0x000d, sig_algs_data),             # signature_algorithms
    build_extension(0x0033, key_share_data),            # key_share
])

# TLS 1.3 ClientHello uses legacy_version=0x0303
ciphers13 = struct.pack('>H', 2) + b'\x13\x01'  # TLS_AES_128_GCM_SHA256
hello13_body = (
    b'\x03\x03'
    + random32
    + session_id
    + ciphers13
    + compression
    + exts13
)
hs13 = build_handshake(0x01, hello13_body)
rec13 = build_tls_record(0x16, 0x0301, hs13)
with open(os.path.join(seeds_dir, 'tls13_client_hello'), 'wb') as f:
    f.write(rec13)

zip_path = os.path.join(out, 'fuzz_tls_server_def_seed_corpus.zip')
with zipfile.ZipFile(zip_path, 'w') as zf:
    for name in os.listdir(seeds_dir):
        zf.write(os.path.join(seeds_dir, name), name)

# _cus variant shares the same seed corpus
import shutil
shutil.copy(zip_path, zip_path.replace('_def_', '_cus_'))
PYEOF
else
	echo "WARNING: libtls.a not found — skipping fuzz_tls_server" >&2
fi

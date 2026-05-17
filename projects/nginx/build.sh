#!/bin/bash -eu
# Copyright 2020 Google Inc.
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
git apply $SRC/add_fuzzers.diff || patch -p1 < $SRC/add_fuzzers.diff

cp -r $SRC/fuzz src/
cp $SRC/make_fuzzers auto/make_fuzzers

# Expose the static DNS-response parser so resolver_fuzzer can drive it
# directly. Drops `static` from the five interesting parser entry points
# in src/core/ngx_resolver.c (declarations on lines ~86-104 and definitions
# scattered through the file). All other `static`s in the file are left
# alone.
python3 - <<'PY'
import re
path = "src/core/ngx_resolver.c"
with open(path) as f:
    s = f.read()
fns = (
    "ngx_resolver_process_response",
    "ngx_resolver_process_a",
    "ngx_resolver_process_srv",
    "ngx_resolver_process_ptr",
    "ngx_resolver_copy",
)
for fn in fns:
    # Declarations: "static void ngx_resolver_foo(" / "static ngx_int_t ngx_resolver_foo("
    s = re.sub(r"^static (void|ngx_int_t) " + fn + r"\(",
               r"\1 " + fn + "(", s, flags=re.M)
    # Definitions: "static void\nngx_resolver_foo(" / "static ngx_int_t\nngx_resolver_foo("
    s = re.sub(r"^static (void|ngx_int_t)\n" + fn + r"\(",
               r"\1\n" + fn + "(", s, flags=re.M)
with open(path, "w") as f:
    f.write(s)
print("resolver statics exposed")
PY

cd src/fuzz
rm -rf genfiles && mkdir genfiles && $SRC/LPM/external.protobuf/bin/protoc http_request_proto.proto --cpp_out=genfiles
cd ../..

auto/configure \
    --with-ld-opt="-Wl,--wrap=listen -Wl,--wrap=setsockopt -Wl,--wrap=bind -Wl,--wrap=shutdown -Wl,--wrap=connect -Wl,--wrap=getpwnam -Wl,--wrap=getgrnam -Wl,--wrap=chmod -Wl,--wrap=chown" \
    --with-cc-opt='-DNGX_DEBUG_PALLOC=1' \
    --with-http_v2_module 
make -f objs/Makefile fuzzers

cp objs/*_fuzzer $OUT/
cp $SRC/fuzz/*.dict $OUT/
cp $SRC/fuzz/*.options $OUT/ 2>/dev/null || true

################################################################################
# Seed corpora
################################################################################
SEEDS_DIR=$(mktemp -d)

# ---- pp_fuzzer seeds (v1 text + v2 binary, incl. one with TLVs) ----
mkdir -p "$SEEDS_DIR/pp"
printf 'PROXY TCP4 1.2.3.4 5.6.7.8 80 81\r\nGET / HTTP/1.0\r\n\r\n'   > "$SEEDS_DIR/pp/v1_tcp4"
printf 'PROXY TCP6 ::1 ::2 12345 443\r\n'                              > "$SEEDS_DIR/pp/v1_tcp6"
printf 'PROXY UNKNOWN\r\n'                                             > "$SEEDS_DIR/pp/v1_unknown"
# v2 minimal IPv4: magic(12) + ver/cmd(0x21) + fam/proto(0x11) + len(12 BE)
printf '\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\x01\x02\x03\x04\x05\x06\x07\x08\x00\x50\x00\x51' > "$SEEDS_DIR/pp/v2_tcp4"
# v2 with one TLV (ALPN=h2): header + 12-byte addrs + tlv type(0x01) + len(2) + "h2" = 17 bytes
printf '\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x11\x01\x02\x03\x04\x05\x06\x07\x08\x00\x50\x00\x51\x01\x00\x02h2' > "$SEEDS_DIR/pp/v2_alpn"

(cd "$SEEDS_DIR/pp" && zip -q -j "$OUT/pp_fuzzer_seed_corpus.zip" ./*)

# ---- parser_fuzzer seeds (selector byte + payload) ----
mkdir -p "$SEEDS_DIR/hp"
# selector 0: request line
printf '\x00GET /index.html?x=1 HTTP/1.1\r\n'                          > "$SEEDS_DIR/hp/sel0_get"
printf '\x00POST http://example.com:80/path HTTP/1.0\r\n'              > "$SEEDS_DIR/hp/sel0_abs_uri"
printf '\x00CONNECT example.com:443 HTTP/1.1\r\n'                      > "$SEEDS_DIR/hp/sel0_connect"
# selector 1: header line (no underscores)
printf '\x01Host: example.com\r\nUser-Agent: ua\r\nContent-Length: 5\r\n\r\n' > "$SEEDS_DIR/hp/sel1_hdrs"
# selector 2: header line (allow underscores)
printf '\x02X_Custom: value\r\n\r\n'                                   > "$SEEDS_DIR/hp/sel2_under"
# selector 3: status line
printf '\x03HTTP/1.1 200 OK\r\n'                                       > "$SEEDS_DIR/hp/sel3_ok"
printf '\x03HTTP/1.0 404 Not Found\r\n'                                > "$SEEDS_DIR/hp/sel3_404"
# selector 4: chunked
printf '\x045\r\nhello\r\n0\r\n\r\n'                                   > "$SEEDS_DIR/hp/sel4_simple"
printf '\x04a;ext=foo\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\n'        > "$SEEDS_DIR/hp/sel4_ext"
# selector 5: complex uri
printf '\x05/a/b/../c/./d?x=1&y=2'                                     > "$SEEDS_DIR/hp/sel5_dotdot"
printf '\x05/path%%20with%%2fencoded'                                   > "$SEEDS_DIR/hp/sel5_enc"
# selector 6: unsafe uri
printf '\x06/abc%%20def'                                               > "$SEEDS_DIR/hp/sel6_safe"
printf '\x06../etc/passwd'                                             > "$SEEDS_DIR/hp/sel6_dotdot"
# selector 7: ngx_http_parse_uri (URI char validator)
printf '\x07/path/with?query=1#frag'                                   > "$SEEDS_DIR/hp/sel7_uri"
printf '\x07/with+plus/'                                               > "$SEEDS_DIR/hp/sel7_plus"
# selector 8: ngx_http_arg — "name\0arg1=v1&arg2=v2"
printf '\x08arg1\x00arg1=hello&arg2=world&arg3='                       > "$SEEDS_DIR/hp/sel8_arg"
# selector 9: ngx_http_split_args — uri with '?'
printf '\x09/foo/bar?a=1&b=2'                                          > "$SEEDS_DIR/hp/sel9_split"
# selector 10/11/12: header chains "name\0Key1: v1\nKey2: v2"
printf '\x0aHost\x00Host: example.com\nHost: other.com\n'              > "$SEEDS_DIR/hp/sel10_multi"
printf '\x0bsid\x00Cookie: sid=abc; foo=bar\nCookie: x=y\n'            > "$SEEDS_DIR/hp/sel11_cookie"
printf '\x0csid\x00Set-Cookie: sid=abc; Path=/; HttpOnly\n'            > "$SEEDS_DIR/hp/sel12_setcookie"

(cd "$SEEDS_DIR/hp" && zip -q -j "$OUT/parser_fuzzer_seed_corpus.zip" ./*)

# ---- inet_fuzzer seeds (selector byte + payload) ----
mkdir -p "$SEEDS_DIR/in"
# selector 0: ngx_inet_addr (IPv4 text)
printf '\x00127.0.0.1'                  > "$SEEDS_DIR/in/sel0_v4_loop"
printf '\x000.0.0.0'                    > "$SEEDS_DIR/in/sel0_v4_any"
printf '\x00255.255.255.255'            > "$SEEDS_DIR/in/sel0_v4_bcast"
# selector 1: ngx_inet6_addr
printf '\x01::1'                        > "$SEEDS_DIR/in/sel1_v6_loop"
printf '\x01fe80::1%%eth0'              > "$SEEDS_DIR/in/sel1_v6_scope"
printf '\x012001:db8::1'                > "$SEEDS_DIR/in/sel1_v6"
# selector 2: ngx_ptocidr
printf '\x0210.0.0.0/8'                 > "$SEEDS_DIR/in/sel2_cidr4"
printf '\x02::/0'                       > "$SEEDS_DIR/in/sel2_cidr6"
# selector 3: ngx_parse_addr
printf '\x03192.168.1.1'                > "$SEEDS_DIR/in/sel3_v4"
printf '\x03::1'                        > "$SEEDS_DIR/in/sel3_v6"
# selector 4: ngx_parse_addr_port
printf '\x04127.0.0.1:8080'             > "$SEEDS_DIR/in/sel4_v4port"
printf '\x04[::1]:443'                  > "$SEEDS_DIR/in/sel4_v6port"
# selector 5: ngx_parse_url (no listen)
printf '\x05http://example.com:80/p'    > "$SEEDS_DIR/in/sel5_url"
printf '\x05unix:/tmp/sock:'            > "$SEEDS_DIR/in/sel5_unix"
# selector 6: ngx_parse_url (listen=1)
printf '\x06*:8080'                     > "$SEEDS_DIR/in/sel6_listen"
printf '\x060.0.0.0:80'                 > "$SEEDS_DIR/in/sel6_listen2"
# selector 7: numeric parsers
printf '\x071234567890'                 > "$SEEDS_DIR/in/sel7_num"
printf '\x070x1aBcDeF'                  > "$SEEDS_DIR/in/sel7_hex"
# selector 8: unescape_uri
printf '\x08/path%%20with%%2Fenc'        > "$SEEDS_DIR/in/sel8_unesc"
# selector 9: escape_uri
printf '\x09a b/c?d=e f'                 > "$SEEDS_DIR/in/sel9_esc"
# selector 10: base64 decode
printf '\x0aSGVsbG8gV29ybGQ='           > "$SEEDS_DIR/in/sel10_b64"

(cd "$SEEDS_DIR/in" && zip -q -j "$OUT/inet_fuzzer_seed_corpus.zip" ./*)

# ---- h2_fuzzer seeds: minimal HTTP/2 frame sequences ----
mkdir -p "$SEEDS_DIR/h2"
# Empty SETTINGS frame (server sends one back, then client should ACK)
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00' > "$SEEDS_DIR/h2/settings_empty"
# SETTINGS ack
printf '\x00\x00\x00\x04\x01\x00\x00\x00\x00' > "$SEEDS_DIR/h2/settings_ack"
# SETTINGS with one entry (HEADER_TABLE_SIZE=4096)
printf '\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x10\x00' > "$SEEDS_DIR/h2/settings_one"
# SETTINGS + HEADERS (:method GET, :path /, :scheme http, :authority localhost)
# HEADERS frame: length=?, type=0x01, flags=0x05 (END_HEADERS|END_STREAM), stream=1
# HPACK: indexed :method GET = 0x82, indexed :path / = 0x84, indexed :scheme http = 0x86,
#        literal :authority "localhost" = 0x41 0x09 "localhost"
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x0e\x01\x05\x00\x00\x00\x01\x82\x84\x86\x41\x09localhost' > "$SEEDS_DIR/h2/headers_get"
# PING
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08' > "$SEEDS_DIR/h2/ping"
# WINDOW_UPDATE for connection (+1000)
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x03\xe8' > "$SEEDS_DIR/h2/window_update"
# GOAWAY
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$SEEDS_DIR/h2/goaway"
# HEADERS with dynamic-table indexing (literal incremental)
printf '\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x14\x01\x05\x00\x00\x00\x01\x82\x84\x86\x40\x07custom1\x05valueA' > "$SEEDS_DIR/h2/headers_dyn"

(cd "$SEEDS_DIR/h2" && zip -q -j "$OUT/h2_fuzzer_seed_corpus.zip" ./*)

# ---- upstream_fuzzer seeds: valid HTTP/1 upstream responses ----
mkdir -p "$SEEDS_DIR/up"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'              > "$SEEDS_DIR/up/200_cl"
printf 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' > "$SEEDS_DIR/up/200_chunked"
printf 'HTTP/1.1 204 No Content\r\n\r\n'                                > "$SEEDS_DIR/up/204"
printf 'HTTP/1.1 301 Moved\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n' > "$SEEDS_DIR/up/301"
printf 'HTTP/1.1 304 Not Modified\r\nETag: "abc"\r\n\r\n'               > "$SEEDS_DIR/up/304"
printf 'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n' > "$SEEDS_DIR/up/500"
printf 'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' > "$SEEDS_DIR/up/100_continue"
# gzip body
printf 'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 20\r\n\r\n\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36' > "$SEEDS_DIR/up/gzip"
# Set-Cookie + cache headers (filter pipeline)
printf 'HTTP/1.1 200 OK\r\nSet-Cookie: id=x; Path=/\r\nCache-Control: max-age=60\r\nETag: "v1"\r\nLast-Modified: Wed, 14 May 2026 00:00:00 GMT\r\nContent-Length: 3\r\n\r\nfoo' > "$SEEDS_DIR/up/cookies"
# X-Accel-Redirect (internal redirect)
printf 'HTTP/1.1 200 OK\r\nX-Accel-Redirect: /internal\r\n\r\n'         > "$SEEDS_DIR/up/x_accel_redirect"
# Trailer headers
printf 'HTTP/1.1 200 OK\r\nTrailer: X-Trailer\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n' > "$SEEDS_DIR/up/trailer"
# Connection: upgrade (tunnel module)
printf 'HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n' > "$SEEDS_DIR/up/upgrade"
# Multiple Set-Cookie
printf 'HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nSet-Cookie: c=3\r\nContent-Length: 0\r\n\r\n' > "$SEEDS_DIR/up/multi_cookie"
# WWW-Authenticate
printf 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="x"\r\nContent-Length: 0\r\n\r\n' > "$SEEDS_DIR/up/auth"

(cd "$SEEDS_DIR/up" && zip -q -j "$OUT/upstream_fuzzer_seed_corpus.zip" ./*)

# ---- resolver_fuzzer seeds: DNS responses ----
# First byte = tcp_flag (0=UDP, 1=TCP), remainder = DNS packet.
mkdir -p "$SEEDS_DIR/dns"
# NOERROR response with one A answer for "example.com": id, flags=0x8180, qd=1, an=1.
printf '\x00\x00\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22' > "$SEEDS_DIR/dns/udp_a"
printf '\x00\x00\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' > "$SEEDS_DIR/dns/udp_aaaa"
printf '\x00\x00\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x10\x06target\x07example\x03com\x00' > "$SEEDS_DIR/dns/udp_cname"
printf '\x00\x00\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05_http\x04_tcp\x07example\x03com\x00\x00\x21\x00\x01\xc0\x0c\x00\x21\x00\x01\x00\x00\x00\x3c\x00\x16\x00\x0a\x00\x14\x00\x50\x06target\x07example\x03com\x00' > "$SEEDS_DIR/dns/udp_srv"
printf '\x00\x00\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x011\x011\x011\x0127\x07in-addr\x04arpa\x00\x00\x0c\x00\x01\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c\x00\x0d\x09localhost\x00' > "$SEEDS_DIR/dns/udp_ptr"
printf '\x00\x00\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\x05nohost\x03com\x00\x00\x01\x00\x01' > "$SEEDS_DIR/dns/udp_nxdomain"
printf '\x00\x00\x12\x34\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00\x05nohost\x03com\x00\x00\x01\x00\x01' > "$SEEDS_DIR/dns/udp_servfail"
printf '\x00\x00\x12\x34\x83\x00\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04' > "$SEEDS_DIR/dns/udp_truncated"
printf '\x00\x00\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x10\xc0\x10\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04' > "$SEEDS_DIR/dns/udp_compress"
printf '\x00\x00\x12\x34\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x05\x06\x07\x08\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x09\x0a\x0b\x0c' > "$SEEDS_DIR/dns/udp_multi_a"
# TCP variants of the same packets (first byte = 1)
printf '\x01\x00\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22' > "$SEEDS_DIR/dns/tcp_a"

(cd "$SEEDS_DIR/dns" && zip -q -j "$OUT/resolver_fuzzer_seed_corpus.zip" ./*)

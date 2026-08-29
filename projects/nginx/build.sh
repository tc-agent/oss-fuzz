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

# Seed corpus for H2 fuzzer: SETTINGS frame after preface
mkdir -p $OUT/http_v2_fuzzer_seed_corpus
printf '\x00\x00\x0c\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x64\x00\x04\x00\x00\xff\xff' > \
    $OUT/http_v2_fuzzer_seed_corpus/settings
# HEADERS frame with minimal HPACK
printf '\x00\x00\x11\x01\x04\x00\x00\x00\x01\x82\x86\x84\x41\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x78\x0f\x03' > \
    $OUT/http_v2_fuzzer_seed_corpus/headers
# PING frame
printf '\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08' > \
    $OUT/http_v2_fuzzer_seed_corpus/ping
# WINDOW_UPDATE frame
printf '\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\xff\xff' > \
    $OUT/http_v2_fuzzer_seed_corpus/window_update
# GOAWAY frame
printf '\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > \
    $OUT/http_v2_fuzzer_seed_corpus/goaway
# RST_STREAM frame
printf '\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x00' > \
    $OUT/http_v2_fuzzer_seed_corpus/rst_stream

# Seed corpus for HTTP parse fuzzer
mkdir -p $OUT/http_parse_fuzzer_seed_corpus
# Request line
printf '\x00GET / HTTP/1.1\r\n' > $OUT/http_parse_fuzzer_seed_corpus/get
printf '\x00POST /path?arg=val HTTP/1.1\r\n' > $OUT/http_parse_fuzzer_seed_corpus/post
printf '\x00DELETE /resource HTTP/1.0\r\n' > $OUT/http_parse_fuzzer_seed_corpus/delete
printf '\x00CONNECT example.com:443 HTTP/1.1\r\n' > $OUT/http_parse_fuzzer_seed_corpus/connect
# Header line
printf '\x01Host: example.com\r\n' > $OUT/http_parse_fuzzer_seed_corpus/header_host
printf '\x01Content-Type: application/json\r\n' > $OUT/http_parse_fuzzer_seed_corpus/header_ct
printf '\x01X-Custom_Header: value with spaces\r\n' > $OUT/http_parse_fuzzer_seed_corpus/header_custom
# Status line
printf '\x02HTTP/1.1 200 OK\r\n' > $OUT/http_parse_fuzzer_seed_corpus/status_200
printf '\x02HTTP/1.1 404 Not Found\r\n' > $OUT/http_parse_fuzzer_seed_corpus/status_404
printf '\x02HTTP/1.0 301 Moved\r\n' > $OUT/http_parse_fuzzer_seed_corpus/status_301
# Chunked encoding
printf '\x03a\r\n0123456789\r\n0\r\n\r\n' > $OUT/http_parse_fuzzer_seed_corpus/chunked_simple
printf '\x03ff\r\n' > $OUT/http_parse_fuzzer_seed_corpus/chunked_hex

# Seed corpus for PROXY protocol fuzzer
mkdir -p $OUT/proxy_protocol_fuzzer_seed_corpus
# PROXY protocol v1 TCP4
printf 'PROXY TCP4 192.168.1.1 192.168.1.2 12345 80\r\n' > \
    $OUT/proxy_protocol_fuzzer_seed_corpus/v1_tcp4
# PROXY protocol v1 TCP6
printf 'PROXY TCP6 ::1 ::1 12345 80\r\n' > \
    $OUT/proxy_protocol_fuzzer_seed_corpus/v1_tcp6
# PROXY protocol v1 UNKNOWN
printf 'PROXY UNKNOWN\r\n' > \
    $OUT/proxy_protocol_fuzzer_seed_corpus/v1_unknown
# PROXY protocol v2 (TCP4)
printf '\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\xc0\xa8\x01\x01\xc0\xa8\x01\x02\x30\x39\x00\x50' > \
    $OUT/proxy_protocol_fuzzer_seed_corpus/v2_tcp4
# PROXY protocol v2 (TCP6)
printf '\r\n\r\n\x00\r\nQUIT\n\x21\x21\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x39\x00\x50' > \
    $OUT/proxy_protocol_fuzzer_seed_corpus/v2_tcp6

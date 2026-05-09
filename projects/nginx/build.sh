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

# Generate seed corpus for proxy_protocol_fuzzer.
pp_seed_dir=$(mktemp -d)
printf 'PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n' > "$pp_seed_dir/v1_tcp4"
printf 'PROXY TCP6 2001:db8::1 2001:db8::2 1234 5678\r\n' > "$pp_seed_dir/v1_tcp6"
printf 'PROXY UNKNOWN\r\n' > "$pp_seed_dir/v1_unknown"
# v2: signature + ver/cmd (PROXY) + AF_INET/STREAM + len(12) + src/dst addrs/ports.
printf '\x0d\x0a\x0d\x0a\x00\x0d\x0aQUIT\x0a\x21\x11\x00\x0c\xc0\xa8\x00\x01\xc0\xa8\x00\x0b\xdc\x04\x01\xbb' \
    > "$pp_seed_dir/v2_tcp4"
# v2 with TLV (alpn=h2): base 28 bytes + TLV {type=0x01, len=2, "h2"} = 33; len = 17.
printf '\x0d\x0a\x0d\x0a\x00\x0d\x0aQUIT\x0a\x21\x11\x00\x11\xc0\xa8\x00\x01\xc0\xa8\x00\x0b\xdc\x04\x01\xbb\x01\x00\x02h2' \
    > "$pp_seed_dir/v2_tcp4_alpn"
zip -j -q "$OUT/proxy_protocol_fuzzer_seed_corpus.zip" "$pp_seed_dir"/*
rm -rf "$pp_seed_dir"

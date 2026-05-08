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

# build project
mkdir build
cd build
cmake -DEVENT__DISABLE_MBEDTLS=ON \
      -DEVENT__DISABLE_OPENSSL=ON \
      -DEVENT__LIBRARY_TYPE=STATIC \
      -DEVENT__DISABLE_TESTS=ON \
      -DEVENT__DISABLE_SAMPLES=ON \
      ../
make -j$(nproc)
make install

# build fuzzer
for fuzzers in $(find $SRC -name '*_fuzzer.cc'); do
  fuzz_basename=$(basename -s .cc $fuzzers)
  $CXX $CXXFLAGS -std=c++17 -I../ -Iinclude \
      $fuzzers $LIB_FUZZING_ENGINE ./lib/libevent.a ./lib/libevent_core.a  \
      ./lib/libevent_pthreads.a ./lib/libevent_extra.a \
      -o $OUT/$fuzz_basename
done

if [[ "$FUZZING_ENGINE" == "honggfuzz" ]]
then
  fuzz_basename=$(basename -s .cc $fuzzers)
  $CC $CFLAGS $LIB_HFND "$HFND_CFLAGS" -Iinclude \
      $SRC/fuzz_request_cb.c $LIB_FUZZING_ENGINE ./lib/libevent.a ./lib/libevent_core.a  \
      ./lib/libevent_pthreads.a ./lib/libevent_extra.a \
      -o $OUT/fuzz_request
fi

# The dictionary is not compatible with AFL
if [ "$FUZZING_ENGINE" != 'afl' ]; then
  cp $SRC/fuzzing/dictionaries/http.dict $OUT/http_fuzzer.dict
  cp $SRC/fuzzing/dictionaries/http.dict $OUT/http_message_fuzzer.dict
  cp $SRC/ws_fuzzer.dict $OUT/ws_fuzzer.dict
fi

# Seed corpora for the harnesses added/refactored in #15465. Without these,
# ClusterFuzz starts the new fuzzers from an empty corpus and corpus pruning
# can take several days to produce the backups consumed by the coverage build.
seed_dir=$WORK/libevent_seeds
mkdir -p $seed_dir/dns_fuzzer $seed_dir/evtag_fuzzer $seed_dir/http_message_fuzzer \
  $seed_dir/listener_fuzzer $seed_dir/ws_fuzzer

# dns_fuzzer: uses FuzzedDataProvider which consumes from the end. The trailing
# byte selects the mode (mod 3): 0=config, 1=server, 2=client. Harness rejects size < 10.
printf 'nameserver 127.0.0.1\n\x00\x00\x00\x00\x00' > $seed_dir/dns_fuzzer/config_mode
printf '\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x01' \
  > $seed_dir/dns_fuzzer/server_query
printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02' > $seed_dir/dns_fuzzer/client_basic

# listener_fuzzer: first 4 bytes are listener flags.
printf '\x00\x00\x00\x00' > $seed_dir/listener_fuzzer/no_flags
printf '\x06\x00\x00\x00' > $seed_dir/listener_fuzzer/close_on_free_exec

# evtag_fuzzer: byte 0 = ops mask, byte 1 = need_tag, then payload (size>=4).
printf '\xff\x01\x00\x00\x00\x04test' > $seed_dir/evtag_fuzzer/all_ops
printf '\x80\x00\x00\x00\x00\x00\x00\x00' > $seed_dir/evtag_fuzzer/header_only

# ws_fuzzer: WebSocket frames written to the peer bufferevent.
printf '\x81\x00' > $seed_dir/ws_fuzzer/text_empty
printf '\x82\x05hello' > $seed_dir/ws_fuzzer/binary_short
printf '\x88\x00' > $seed_dir/ws_fuzzer/close_empty
printf '\x89\x00' > $seed_dir/ws_fuzzer/ping_empty

# http_message_fuzzer: first byte = mode bitmask, second = extra (size>=6).
printf '\x01\x00GET / HTTP/1.1\r\nHost: x\r\n\r\n' > $seed_dir/http_message_fuzzer/req_get
printf '\x02\x00HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' > $seed_dir/http_message_fuzzer/resp_200
printf '\x10\x00/path?a=1&b=hello%%20world' > $seed_dir/http_message_fuzzer/uri_query
printf '\x40\x00X-Foo: bar\nHost: example\n' > $seed_dir/http_message_fuzzer/headers

for target in dns_fuzzer evtag_fuzzer http_message_fuzzer listener_fuzzer ws_fuzzer; do
  rm -f $OUT/${target}_seed_corpus.zip
  (cd $seed_dir/$target && zip -q $OUT/${target}_seed_corpus.zip *)
done

# Build the project tests for Chronos
mkdir -p $SRC/libevent/build-tests
cd $SRC/libevent/build-tests
cmake -DEVENT__DISABLE_TESTS=OFF \
      -DEVENT__DISABLE_MBEDTLS=ON \
      -DEVENT__DISABLE_OPENSSL=ON \
      -DEVENT__LIBRARY_TYPE=STATIC \
      -DEVENT__DISABLE_SAMPLES=ON \
      ..
make -j$(nproc)

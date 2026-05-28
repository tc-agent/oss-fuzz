#!/bin/bash -eu
# Copyright 2021 Google LLC
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
cd c++
autoreconf -i
./configure --disable-shared
make -j$(nproc)
make -j$(nproc) capnp-llvm-fuzzer-testcase
cp *fuzzer* $OUT/

# Build extra harnesses for code paths the default
# capnp-llvm-fuzzer-testcase does not exercise.
EXTRA_LIBS="libcapnp-test.a \
            .libs/libcapnpc.a \
            .libs/libcapnp-json.a \
            .libs/libcapnp-rpc.a \
            .libs/libcapnp.a \
            .libs/libkj-async.a \
            .libs/libkj.a"

for harness in "$SRC"/capnp-packed-fuzzer.c++ \
               "$SRC"/capnp-json-fuzzer.c++ \
               "$SRC"/capnp-text-fuzzer.c++ \
               "$SRC"/capnp-message-fuzzer.c++ \
               "$SRC"/capnp-encoding-fuzzer.c++; do
    name=$(basename "$harness" .c++)
    $CXX $CXXFLAGS -std=gnu++23 -stdlib=libc++ \
        -I src \
        "$harness" \
        $EXTRA_LIBS \
        $LIB_FUZZING_ENGINE \
        -lpthread -ldl -lz \
        -o "$OUT/$name"
done

# Build seed corpora directly from the upstream test-data tree so we don't
# need to vendor binary fixtures into the oss-fuzz repo.
TD="$SRC/capnproto/c++/src/capnp/testdata"
# The `flat` / `packedflat` test-data files are unframed (capnp `--flat`)
# encodings, which the framed Packed/InputStream/FlatArray readers cannot parse;
# only the framed fixtures are used as seeds.
zip -j "$OUT/capnp-packed-fuzzer_seed_corpus.zip" \
    "$TD/packed" "$TD/segmented-packed"
# The unpacked-message readers (the upstream capnp-llvm-fuzzer-testcase and our
# capnp-message-fuzzer) ship with no seeds in the current OSS-Fuzz integration,
# so they have to rediscover the wire format from scratch. Seed them with the
# golden serialized messages from the upstream test-data tree.
zip -j "$OUT/capnp-llvm-fuzzer-testcase_seed_corpus.zip" \
    "$TD/binary" "$TD/segmented" "$TD/lists.binary"
zip -j "$OUT/capnp-message-fuzzer_seed_corpus.zip" \
    "$TD/binary" "$TD/segmented" "$TD/lists.binary"
zip -j "$OUT/capnp-json-fuzzer_seed_corpus.zip" \
    "$TD/short.json" "$TD/pretty.json" "$TD/annotated.json"
zip -j "$OUT/capnp-text-fuzzer_seed_corpus.zip" \
    "$TD/short.txt" "$TD/pretty.txt"

# Encoding fuzzer: a handful of human-readable codec samples to seed the Base64
# / hex / percent-encoding / escape decoders.
ENC_SEEDS=$(mktemp -d)
printf 'SGVsbG8sIHdvcmxkIQ==' > "$ENC_SEEDS/base64.txt"
printf '48656c6c6f' > "$ENC_SEEDS/hex.txt"
printf 'a%%20b%%2Fc+d&e=f' > "$ENC_SEEDS/form.txt"
printf 'a\\x41\\102\\n\\t"q"' > "$ENC_SEEDS/cescape.txt"
zip -j "$OUT/capnp-encoding-fuzzer_seed_corpus.zip" "$ENC_SEEDS"/*

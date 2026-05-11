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

export ASAN_OPTIONS="detect_leaks=0"

export OSS_CFLAGS="$CFLAGS -g"

# Use lld for coverage builds: GNU ld fails on DWARF-5 FORM 0x25 emitted by
# newer clang when linking coverage-instrumented objects.
if [ "${SANITIZER:-}" = "coverage" ]; then
  OSS_CFLAGS="$OSS_CFLAGS -fuse-ld=lld"
fi

sed -i 's/CFLAGS        =/CFLAGS        = ${OSS_CFLAGS} /g' ./Makefile
sed -i 's/LDFLAGS       =/LDFLAGS       = ${OSS_CFLAGS} /g' ./Makefile

make

# Remove main function and create an archive
cd ./src
sed -i 's/int main (/int main2 (/g' ./dnsmasq.c

rm dnsmasq.o
$CC $CFLAGS -c dnsmasq.c -o dnsmasq.o -I./ -DVERSION=\'\"UNKNOWN\"\'
ar cr libdnsmasq.a *.o

# Rename C++ keywords used as identifiers in dnsmasq.h so the C++ harness
# (fuzz_util.cc) can include the header.
sed -i 's/class/class2/g' ./dnsmasq.h
sed -i 's/new/new2/g' ./dnsmasq.h

# Always use lld for harness links: GNU ld trips on DWARF-5 FORM 0x25 from
# newer clang.
LDFLAGS_EXTRA="-fuse-ld=lld"

# Build the C++ harness (fuzz_util)
$CXX $CXXFLAGS -c $SRC/fuzz_util.cc -I./ -I$SRC/ -DVERSION=\'\"UNKNOWN\"\' -g
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $LDFLAGS_EXTRA ./fuzz_util.o libdnsmasq.a -o $OUT/fuzz_util

# Build the C harnesses. They link against libdnsmasq.a (which contains
# its own LLVMFuzzerTestOneInput-free dnsmasq.o).
for h in fuzz_rfc1035 fuzz_auth fuzz_dhcp fuzz_dhcp6; do
  $CC $CFLAGS -c $SRC/${h}.c -I./ -I$SRC/ -DVERSION=\'\"UNKNOWN\"\' -g -o ${h}.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $LDFLAGS_EXTRA ./${h}.o libdnsmasq.a -o $OUT/${h}
done

# Copy per-harness .options files for fuzzer runtime configuration.
for f in $SRC/fuzz_*.options; do
  [ -f "$f" ] && cp "$f" "$OUT/"
done

# Generate seed corpora from the Python generators (kept in $SRC/scripts/).
# Seeds are produced from human-readable code so we don't commit binary blobs.
mkdir -p /tmp/seeds/fuzz_util /tmp/seeds/fuzz_rfc1035 /tmp/seeds/fuzz_auth \
         /tmp/seeds/fuzz_dhcp /tmp/seeds/fuzz_dhcp6
python3 "$SRC/scripts/gen_seeds.py" /tmp/seeds
python3 "$SRC/scripts/gen_dhcp_seeds.py" /tmp/seeds/fuzz_dhcp /tmp/seeds/fuzz_dhcp6
for h in fuzz_util fuzz_rfc1035 fuzz_auth fuzz_dhcp fuzz_dhcp6; do
  if [ -d "/tmp/seeds/$h" ]; then
    (cd "/tmp/seeds/$h" && zip -r -q "$OUT/${h}_seed_corpus.zip" .)
  fi
done

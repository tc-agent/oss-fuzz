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

# Enable DNSSEC so dnssec.c is compiled in and dnssec_validate_reply is
# reachable from fuzz_dns_reply.
COPTS="-DHAVE_DNSSEC"
export COPTS

# Expose one_opt() so the option-parsing fuzzer can call it directly.
sed -i 's/^static int one_opt(/int one_opt(/' ./src/option.c
# Expose process_reply() so fuzz_dns_reply can call it directly.
sed -i 's/^static size_t process_reply(/size_t process_reply(/' ./src/forward.c

# Rename the real die() so we can supply a longjmp-based replacement that
# doesn't terminate the fuzzer process.
sed -i 's/^void die(/void die_orig(/' ./src/log.c
# Strip ATTRIBUTE_NORETURN only from the die() declaration so callers don't
# treat our (returning) replacement as no-return.
sed -i 's|^void die(char \*message, char \*arg1, int exit_code) ATTRIBUTE_NORETURN;|void die(char *message, char *arg1, int exit_code);|' ./src/dnsmasq.h

# Append the fuzz-aware die() to dnsmasq.c so libdnsmasq.a exports it.
cat >> ./src/dnsmasq.c <<'EOF'

#include <setjmp.h>
#include <unistd.h>
jmp_buf fuzz_die_jmp;
int fuzz_die_active = 0;
void die(char *message, char *arg1, int exit_code) {
  (void)message; (void)arg1;
  if (fuzz_die_active) longjmp(fuzz_die_jmp, 1);
  _exit(exit_code);
}
EOF

make COPTS="$COPTS"

# Remove main function and create an archive
cd ./src
sed -i 's/int main (/int main2 (/g' ./dnsmasq.c

rm dnsmasq.o
$CC $CFLAGS $COPTS -c dnsmasq.c -o dnsmasq.o -I./ -DVERSION=\'\"UNKNOWN\"\'
ar cr libdnsmasq.a *.o

# Rename C++ keywords used as identifiers in dnsmasq.h so the C++ harness
# (fuzz_util.cc) can include the header.
sed -i 's/class/class2/g' ./dnsmasq.h
sed -i 's/new/new2/g' ./dnsmasq.h

# Always use lld for harness links: GNU ld trips on DWARF-5 FORM 0x25 from
# newer clang.
LDFLAGS_EXTRA="-fuse-ld=lld"

NETTLE_LIBS="$(pkg-config --libs nettle hogweed 2>/dev/null) -lgmp"

# Build the C++ harness (fuzz_util)
$CXX $CXXFLAGS $COPTS -c $SRC/fuzz_util.cc -I./ -I$SRC/ -DVERSION=\'\"UNKNOWN\"\' -g
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $LDFLAGS_EXTRA ./fuzz_util.o libdnsmasq.a $NETTLE_LIBS -o $OUT/fuzz_util

# Build the C harnesses. They link against libdnsmasq.a (which contains
# its own LLVMFuzzerTestOneInput-free dnsmasq.o).
for h in fuzz_rfc1035 fuzz_auth fuzz_dhcp fuzz_dhcp6 fuzz_option fuzz_dns_reply; do
  $CC $CFLAGS $COPTS -c $SRC/${h}.c -I./ -I$SRC/ -DVERSION=\'\"UNKNOWN\"\' -g -o ${h}.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $LDFLAGS_EXTRA ./${h}.o libdnsmasq.a $NETTLE_LIBS -o $OUT/${h}
done

# Copy per-harness .options files for fuzzer runtime configuration.
for f in $SRC/fuzz_*.options; do
  [ -f "$f" ] && cp "$f" "$OUT/"
done

# Generate seed corpora from the Python generators (kept in $SRC/scripts/).
# Seeds are produced from human-readable code so we don't commit binary blobs.
mkdir -p /tmp/seeds/fuzz_util /tmp/seeds/fuzz_rfc1035 /tmp/seeds/fuzz_auth \
         /tmp/seeds/fuzz_dhcp /tmp/seeds/fuzz_dhcp6 /tmp/seeds/fuzz_option \
         /tmp/seeds/fuzz_dns_reply
python3 "$SRC/scripts/gen_seeds.py" /tmp/seeds
python3 "$SRC/scripts/gen_dhcp_seeds.py" /tmp/seeds/fuzz_dhcp /tmp/seeds/fuzz_dhcp6
python3 "$SRC/scripts/gen_option_seeds.py" /tmp/seeds/fuzz_option
python3 "$SRC/scripts/gen_reply_seeds.py" /tmp/seeds/fuzz_dns_reply
for h in fuzz_util fuzz_rfc1035 fuzz_auth fuzz_dhcp fuzz_dhcp6 fuzz_option fuzz_dns_reply; do
  if [ -d "/tmp/seeds/$h" ]; then
    (cd "/tmp/seeds/$h" && zip -r -q "$OUT/${h}_seed_corpus.zip" .)
  fi
done

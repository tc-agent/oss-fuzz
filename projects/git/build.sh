#!/bin/bash -eu

# build zlib
pushd "$SRC/zlib"
./configure --static --prefix="$WORK"
make -j$(nproc) CFLAGS="$CFLAGS -fPIC"
make install
popd
export ZLIB_PATH=$WORK

# Enable a timeout for lockfiles rather than exit immediately. This is to
# overcome in case multiple processes try to lock a file around the same
# time.
sed -i 's/hold_lock_file_for_update_timeout(lk, path, flags, 0);/hold_lock_file_for_update_timeout(lk, path, flags, 5000);/g' lockfile.h

# Copy new harness sources into the oss-fuzz directory
cp $SRC/harnesses/*.c oss-fuzz/

# Patch Makefile to include new harnesses in FUZZ_OBJS
sed -i '/^FUZZ_OBJS += oss-fuzz\/fuzz-url-decode-mem.o$/a \
FUZZ_OBJS += oss-fuzz/fuzz-parse-commit.o\
FUZZ_OBJS += oss-fuzz/fuzz-parse-tag.o\
FUZZ_OBJS += oss-fuzz/fuzz-tree-walk.o\
FUZZ_OBJS += oss-fuzz/fuzz-fsck.o\
FUZZ_OBJS += oss-fuzz/fuzz-refname.o' Makefile

# Override GITLIBS to exclude common-main.o. The fuzzing engine (libFuzzer or AFL)
# provides its own main() that calls LLVMFuzzerTestOneInput().
# For AFL, we also need --whole-archive to force include the AFL driver's main().
if [ "${FUZZING_ENGINE:-}" = "afl" ]; then
  FUZZING_ENGINE_FLAGS="-Wl,--whole-archive $LIB_FUZZING_ENGINE -Wl,--no-whole-archive"
else
  FUZZING_ENGINE_FLAGS="$LIB_FUZZING_ENGINE"
fi

# build all fuzzers (upstream + new harnesses)
make -j$(nproc) CC=$CC CXX=$CXX CFLAGS="$CFLAGS" \
  FUZZ_CXXFLAGS="$CXXFLAGS" \
  LIB_FUZZING_ENGINE="$FUZZING_ENGINE_FLAGS" \
  GITLIBS=libgit.a fuzz-all

FUZZERS=""
FUZZERS="$FUZZERS fuzz-commit-graph"
FUZZERS="$FUZZERS fuzz-config"
FUZZERS="$FUZZERS fuzz-credential-from-url-gently"
FUZZERS="$FUZZERS fuzz-date"
FUZZERS="$FUZZERS fuzz-pack-headers"
FUZZERS="$FUZZERS fuzz-pack-idx"
FUZZERS="$FUZZERS fuzz-parse-attr-line"
FUZZERS="$FUZZERS fuzz-url-decode-mem"
FUZZERS="$FUZZERS fuzz-parse-commit"
FUZZERS="$FUZZERS fuzz-parse-tag"
FUZZERS="$FUZZERS fuzz-tree-walk"
FUZZERS="$FUZZERS fuzz-fsck"
FUZZERS="$FUZZERS fuzz-refname"

# copy fuzzers
for fuzzer in $FUZZERS ; do
  cp oss-fuzz/$fuzzer $OUT
done

for fuzzer in $FUZZERS ; do
  cat >$OUT/$fuzzer.options << EOF
[libfuzzer]
detect_leaks = 0
EOF
done

# copy seed corpora
for corpus in $SRC/harnesses/*_seed_corpus.zip ; do
  [ -f "$corpus" ] && cp "$corpus" $OUT/
done

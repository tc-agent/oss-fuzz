#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Stage the additional harnesses into the upstream oss-fuzz/ directory and
# register them in the Makefile so the existing fuzz-all rule picks them up
# (preserving GITLIBS/EXTLIBS link flags).
NEW_FUZZERS="fuzz-parse-commit fuzz-parse-tag fuzz-tree-walk fuzz-fsck fuzz-refname"
for f in $NEW_FUZZERS; do
  cp "$SRC/$f.c" "oss-fuzz/$f.c"
done

ADD_OBJS=""
for f in $NEW_FUZZERS; do
  ADD_OBJS="${ADD_OBJS}FUZZ_OBJS += oss-fuzz/$f.o\n"
done
sed -i "/^FUZZ_OBJS += oss-fuzz\/fuzz-url-decode-mem.o\$/a ${ADD_OBJS%\\n}" Makefile

# Override GITLIBS to exclude common-main.o. The fuzzing engine (libFuzzer or AFL)
# provides its own main() that calls LLVMFuzzerTestOneInput().
# For AFL, we also need --whole-archive to force include the AFL driver's main().
if [ "${FUZZING_ENGINE:-}" = "afl" ]; then
  FUZZING_ENGINE_FLAGS="-Wl,--whole-archive $LIB_FUZZING_ENGINE -Wl,--no-whole-archive"
else
  FUZZING_ENGINE_FLAGS="$LIB_FUZZING_ENGINE"
fi

# build fuzzers
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

# package seed corpora for the new harnesses
for f in $NEW_FUZZERS; do
  if [ -d "$SRC/seeds/$f" ]; then
    (cd "$SRC/seeds/$f" && zip -q -r "$OUT/${f}_seed_corpus.zip" .)
  fi
done


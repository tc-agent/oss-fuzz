#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

# Build FFmpeg as static libraries so coverage instrumentation propagates.
# Previously FFmpeg was built in the Dockerfile with --enable-shared and
# plain clang, which meant coverage builds produced no .profraw files.
cd $SRC/ffmpeg
./configure --prefix=/usr --cc=$CC --cxx=$CXX \
    --ld="$CXX $CXXFLAGS" \
    --extra-cflags="$CFLAGS" \
    --extra-ldflags="$CFLAGS" \
    --enable-static --disable-shared \
    --disable-doc --disable-programs --disable-debug \
    --disable-asm \
    --pkg-config-flags="--static"
make -j$(nproc)
make install

cd $SRC/ffms2
# autoreconf breaks when sanitizer/coverage flags are in the environment,
# so clear them for the bootstrap step only.
NOCONFIGURE=1 CFLAGS= CXXFLAGS= LDFLAGS= ./autogen.sh
./configure --prefix=/usr --enable-static --disable-shared
make -j$(nproc)
make install

for f in $SRC/*_fuzzer.cc; do
  fuzzer=$(basename "$f" _fuzzer.cc)
  $CXX $CXXFLAGS -std=c++11 -I/usr/include \
    $SRC/${fuzzer}_fuzzer.cc -o $OUT/${fuzzer}_fuzzer \
    $LIB_FUZZING_ENGINE \
    -lffms2 \
    $(pkg-config --libs --static libavformat libavcodec libswscale libswresample libavutil) \
    -lpthread -lz -lm
done

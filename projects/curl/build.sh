#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# Run the OSS-Fuzz script in the curl-fuzzer project.

if [[ ! -z "${REPLAY_ENABLED-}" ]]; then
  # If we don't do this, the curl library won't rebuild.
  rm -f $SRC/curl_fuzzer/build/curl-install/lib/libcurl.a
  pushd $SRC/curl
  make install
  popd
fi

./ossfuzz.sh

# Compile standalone harnesses against the already-built static libs.
BUILD=$SRC/curl_fuzzer/build
CURL_INCLUDE=$BUILD/curl-install/include
LIBS="$BUILD/curl-install/lib/libcurl.a \
      $BUILD/nghttp2-install/lib/libnghttp2.a \
      $BUILD/openssl-install/lib/libssl.a \
      $BUILD/openssl-install/lib/libcrypto.a \
      $BUILD/zlib-install/lib/libz.a \
      $BUILD/zstd-install/lib/libzstd.a \
      $BUILD/libidn2-install/lib/libidn2.a \
      $BUILD/openldap-install/lib/libldap.a \
      $BUILD/openldap-install/lib/liblber.a"

for harness in fuzz_parsedate fuzz_escape fuzz_cookie fuzz_mime fuzz_netrc fuzz_hsts fuzz_altsvc; do
  $CXX $CXXFLAGS -DCURL_DISABLE_DEPRECATION \
    -I"$CURL_INCLUDE" \
    "$SRC/harnesses/${harness}.cc" \
    -o "$OUT/${harness}" \
    $LIB_FUZZING_ENGINE \
    $LIBS \
    -lpthread -lm

  # Zip seed corpus if present
  if [ -d "$SRC/seeds/${harness}" ]; then
    zip -j "$OUT/${harness}_seed_corpus.zip" "$SRC/seeds/${harness}/"*
  fi
done

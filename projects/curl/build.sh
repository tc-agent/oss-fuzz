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

# Build additional standalone harnesses from $SRC/harnesses/
# These link against the same libcurl and dependencies built by ossfuzz.sh.

CURL_INSTALL=$SRC/curl_fuzzer/build/curl-install
NGHTTP2_INSTALL=$SRC/curl_fuzzer/build/nghttp2-install
ZLIB_INSTALL=$SRC/curl_fuzzer/build/zlib-install
ZSTD_INSTALL=$SRC/curl_fuzzer/build/zstd-install
LIBIDN2_INSTALL=$SRC/curl_fuzzer/build/libidn2-install
OPENSSL_INSTALL=$SRC/curl_fuzzer/build/openssl-install
OPENLDAP_INSTALL=$SRC/curl_fuzzer/build/openldap-install

INCLUDES="-I${CURL_INSTALL}/include"

STATIC_LIBS="${CURL_INSTALL}/lib/libcurl.a"

# Add optional dependency libraries if they exist
for lib in \
  "${NGHTTP2_INSTALL}/lib/libnghttp2.a" \
  "${OPENSSL_INSTALL}/lib/libssl.a" \
  "${OPENSSL_INSTALL}/lib/libcrypto.a" \
  "${ZLIB_INSTALL}/lib/libz.a" \
  "${ZSTD_INSTALL}/lib/libzstd.a" \
  "${LIBIDN2_INSTALL}/lib/libidn2.a" \
  "${OPENLDAP_INSTALL}/lib/libldap.a" \
  "${OPENLDAP_INSTALL}/lib/liblber.a"
do
  if [ -f "$lib" ]; then
    STATIC_LIBS="$STATIC_LIBS $lib"
  fi
done

HARNESS_DIR=$SRC/harnesses
if [ -d "$HARNESS_DIR" ]; then
  for harness_src in "$HARNESS_DIR"/*.cc; do
    [ -f "$harness_src" ] || continue
    harness_name=$(basename "$harness_src" .cc)
    echo "Building harness: $harness_name"
    $CXX $CXXFLAGS $INCLUDES \
      -DCURL_DISABLE_DEPRECATION \
      "$harness_src" \
      -o "${OUT}/${harness_name}" \
      $STATIC_LIBS \
      $LIB_FUZZING_ENGINE \
      -lpthread -lm
  done
fi

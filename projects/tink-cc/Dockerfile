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

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make pkg-config

# Pre-install abseil-cpp and protobuf so they are not recompiled during
# coverage builds (which add instrumentation flags and make the full
# from-source build exceed the OSS-Fuzz timeout).
# Versions match tink-cc's cmake/TinkWorkspace.cmake pinned versions.

RUN cd /tmp && \
    curl -sL https://github.com/abseil/abseil-cpp/releases/download/20260107.0/abseil-cpp-20260107.0.tar.gz | tar xz && \
    cd abseil-cpp-20260107.0 && mkdir build && cd build && \
    cmake .. -DCMAKE_CXX_STANDARD=17 -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
             -DABSL_BUILD_TESTING=OFF -DABSL_ENABLE_INSTALL=ON && \
    make -j$(nproc) install && \
    ldconfig && cd /tmp && rm -rf abseil-cpp-20260107.0

RUN cd /tmp && \
    curl -sL https://github.com/protocolbuffers/protobuf/archive/refs/tags/v30.2.tar.gz | tar xz && \
    cd protobuf-* && mkdir build && cd build && \
    cmake .. -DCMAKE_CXX_STANDARD=17 -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
             -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_ABSL_PROVIDER=package && \
    make -j$(nproc) install && \
    ldconfig && cd /tmp && rm -rf protobuf-*

RUN git clone --depth 1 https://github.com/tink-crypto/tink-cc

RUN mkdir $SRC/tink-cc/fuzzing
COPY fuzzing_CMake $SRC/tink-cc/fuzzing/CMakeLists.txt
COPY tink_encrypt_decrypt_fuzzer.cc $SRC/tink-cc/fuzzing/tink_encrypt_decrypt_fuzzer.cc
COPY build.sh $SRC/

WORKDIR tink-cc

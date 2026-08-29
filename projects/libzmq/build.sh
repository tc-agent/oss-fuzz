#!/bin/bash -eu
# Copyright 2020 Google Inc.
# Copyright 2020 Luca Boccassi <bluca@debian.org>
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

${SRC}/libzmq/builds/fuzz/ci_build.sh

# Build additional in-process decoder harnesses.
# After ci_build.sh, platform.hpp is generated in ${SRC}/libzmq/src/ and
# the static libraries are installed under /tmp/zmq_install_dir/install_prefix/.
ZMQINST=/tmp/zmq_install_dir/install_prefix

for harness in ${SRC}/test_*_fuzzer.cpp; do
    name=$(basename "${harness}" .cpp)
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        -std=c++11 \
        -I${SRC}/libzmq/src \
        -I${SRC}/libzmq/include \
        "${harness}" \
        "${ZMQINST}/lib/libzmq.a" \
        "${ZMQINST}/lib/libsodium.a" \
        -lpthread \
        -o "${OUT}/${name}"
done

# Generate seed corpora for the in-process decoder harnesses.
SEED_TMP=$(mktemp -d)
python3 "${SRC}/generate_seeds.py" "${SEED_TMP}"
for seed_dir in "${SEED_TMP}"/*/; do
    name=$(basename "${seed_dir}")
    if [ -d "${seed_dir}" ] && [ "$(ls -A "${seed_dir}")" ]; then
        zip -j "${OUT}/${name}_seed_corpus.zip" "${seed_dir}"/*
    fi
done
rm -rf "${SEED_TMP}"

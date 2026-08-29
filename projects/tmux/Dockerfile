# Copyright 2020 Google LLC
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
RUN apt-get update && apt-get install -y autoconf automake bison pkg-config \
    ncurses-dev libtool

RUN git clone https://github.com/libevent/libevent.git && \
    cd libevent && \
    mkdir build && \
    cd build && \
    cmake -DEVENT__DISABLE_MBEDTLS=ON -DEVENT__DISABLE_OPENSSL=ON -DEVENT__LIBRARY_TYPE=STATIC -DEVENT__DISABLE_TESTS=ON -DEVENT__DISABLE_SAMPLES=ON ../ && \
    make && make install

RUN git clone --depth 1 https://github.com/tmux/tmux.git
RUN git clone --depth 1 https://github.com/tmux/tmux-fuzzing-corpus.git
WORKDIR tmux
COPY build.sh $SRC/

# New harnesses not yet in upstream tmux/fuzz/
COPY colour-fuzzer.c \
     colour-fuzzer.options \
     colour-fuzzer.dict \
     key-string-fuzzer.c \
     key-string-fuzzer.options \
     key-string-fuzzer.dict \
     $SRC/

# Seed corpora for all non-input fuzzers
COPY seeds/format-fuzzer/ $SRC/format-fuzzer-seeds/
COPY seeds/style-fuzzer/ $SRC/style-fuzzer-seeds/
COPY seeds/cmd-parse-fuzzer/ $SRC/cmd-parse-fuzzer-seeds/
COPY seeds/colour-fuzzer/ $SRC/colour-fuzzer-seeds/
COPY seeds/key-string-fuzzer/ $SRC/key-string-fuzzer-seeds/

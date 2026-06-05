# Copyright 2024 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake libtool build-essential cmake \
    libexif-dev libglib2.0-dev libavahi-glib-dev liblcms2-dev libfreetype6-dev libfontconfig1-dev \
    libpoppler-cpp-dev poppler-utils libunistring-dev libsystemd-dev libcap-dev gettext autopoint \
    libcups2-dev libavahi-client-dev ghostscript mupdf-tools

# Build QPDF 11.x from source — cups-filters 1.x now requires QPDF >= 11
# (the base-builder ships QPDF 9.x which lacks replaceKey() and POINTERHOLDER_TRANSITION support)
# Unset LIB_FUZZING_ENGINE so QPDF's own fuzz targets use the standalone runner
# instead of linking against the not-yet-available fuzzing engine library.
# Force the new C++11 ABI so QPDF symbols match what cups-filters expects at link time.
RUN git clone --depth 1 --branch v11.10.1 https://github.com/qpdf/qpdf.git /tmp/qpdf && \
    cd /tmp/qpdf && \
    env -u LIB_FUZZING_ENGINE cmake -S . -B build \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_BUILD_TYPE=Release \
        "-DCMAKE_CXX_FLAGS=-D_GLIBCXX_USE_CXX11_ABI=1" && \
    env -u LIB_FUZZING_ENGINE cmake --build build --parallel $(nproc) && \
    cmake --install build && \
    ldconfig && \
    rm -rf /tmp/qpdf

# ubuntu 20.04 only supports cups-filters 1.x
RUN git clone --depth 1 -b "1.x" https://github.com/OpenPrinting/cups-filters.git
RUN git clone --depth 1 https://github.com/OpenPrinting/fuzzing.git

RUN cp $SRC/fuzzing/projects/cups-filters/oss_fuzz_build.sh $SRC/build.sh

WORKDIR $SRC/cups-filters
COPY run_tests.sh $SRC/

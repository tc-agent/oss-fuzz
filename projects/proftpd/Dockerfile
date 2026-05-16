# Copyright 2021 Google Inc.
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
RUN apt-get update && apt-get install -y make autoconf automake libtool \
  pkg-config cmake check
RUN git clone --depth 1 https://github.com/proftpd/proftpd
WORKDIR proftpd
COPY build.sh $SRC/
COPY netacl_fuzzer.c logfmt_fuzzer.c ftpaccess_fuzzer.c cmd_fuzzer.c $SRC/
COPY ftpaccess_fuzzer.dict $SRC/
COPY netacl_seeds $SRC/netacl_seeds
COPY logfmt_seeds $SRC/logfmt_seeds
COPY ftpaccess_seeds $SRC/ftpaccess_seeds
COPY cmd_seeds $SRC/cmd_seeds

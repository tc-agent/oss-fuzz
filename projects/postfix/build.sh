#!/bin/bash -eu
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

cd postfix
make makefiles CCARGS="${CFLAGS} -DNO_NIS -DNO_NISPLUS"
make
BASE=$PWD

POSTFIX_FUZZ_CFLAGS="$CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS \
    -DDEF_SHLIB_DIR=\"no\" -UUSE_DYNAMIC_MAPS -DNO_EAI \
    -DDEF_SMTPUTF8_ENABLE=\"no\" -g -O -DLINUX4 -Wformat -Wno-comment -fno-common"

# Compile fuzzers that live in src/global include space.
cd ${BASE}/src/global
for f in fuzz_tok822 fuzz_mime fuzz_haproxy fuzz_encode fuzz_header fuzz_addr fuzz_cidr fuzz_attr; do
    $CC $POSTFIX_FUZZ_CFLAGS -I. -I../../include -c $SRC/harnesses/${f}.c -o ${f}.o
done

# Compile fuzz_smtpd_token: needs src/smtpd include path and links smtpd_token.o.
cd ${BASE}/src/smtpd
$CC $POSTFIX_FUZZ_CFLAGS -I. -I../../include -c $SRC/harnesses/fuzz_smtpd_token.c -o fuzz_smtpd_token.o
$CC $POSTFIX_FUZZ_CFLAGS -I. -I../../include -c smtpd_token.c -o smtpd_token.o

# Link fuzzers
cd ${BASE}
COMMON_LIBS="./lib/libglobal.a ./lib/libutil.a -ldb"

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_tok822.o      -o $OUT/fuzz_tok822      $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_mime.o        -o $OUT/fuzz_mime        $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_haproxy.o     -o $OUT/fuzz_haproxy     $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_encode.o      -o $OUT/fuzz_encode      $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_header.o      -o $OUT/fuzz_header      $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_addr.o        -o $OUT/fuzz_addr        $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_cidr.o        -o $OUT/fuzz_cidr        $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_attr.o        -o $OUT/fuzz_attr        $COMMON_LIBS
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    ./src/smtpd/fuzz_smtpd_token.o ./src/smtpd/smtpd_token.o       -o $OUT/fuzz_smtpd_token $COMMON_LIBS

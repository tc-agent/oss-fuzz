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

# Compile fuzzers
cd ${BASE}/src/global
$CC $CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR=\"no\" \
               -UUSE_DYNAMIC_MAPS -I. -I../../include -DNO_EAI -DDEF_SMTPUTF8_ENABLE=\"no\" \
                -g -O -DLINUX4 -Wformat -Wno-comment -fno-common -c $SRC/fuzz_tok822.c
$CC $CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR=\"no\" \
               -UUSE_DYNAMIC_MAPS -I. -I../../include -DNO_EAI -DDEF_SMTPUTF8_ENABLE=\"no\" \
                -g -O -DLINUX4 -Wformat -Wno-comment -fno-common -c $SRC/fuzz_mime.c
$CC $CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR=\"no\" \
               -UUSE_DYNAMIC_MAPS -I. -I../../include -DNO_EAI -DDEF_SMTPUTF8_ENABLE=\"no\" \
                -g -O -DLINUX4 -Wformat -Wno-comment -fno-common -c $SRC/fuzz_haproxy.c

# Compile fuzzers in src/util/ (for util library functions)
cd ${BASE}/src/util
$CC $CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR=\"no\" \
               -UUSE_DYNAMIC_MAPS -I. -I../../include -DNO_EAI -DDEF_SMTPUTF8_ENABLE=\"no\" \
                -g -O -DLINUX4 -Wformat -Wno-comment -fno-common -c $SRC/fuzz_dict_regexp.c
$CC $CFLAGS -DHAS_DEV_URANDOM -DSNAPSHOT -UUSE_DYNAMIC_LIBS -DDEF_SHLIB_DIR=\"no\" \
               -UUSE_DYNAMIC_MAPS -I. -I../../include -DNO_EAI -DDEF_SMTPUTF8_ENABLE=\"no\" \
                -g -O -DLINUX4 -Wformat -Wno-comment -fno-common -c $SRC/fuzz_dict_cidr.c

# Link fuzzers
cd ${BASE}
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_tok822.o \
  -o $OUT/fuzz_tok822 ./lib/libglobal.a ./lib/libutil.a
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_mime.o -o $OUT/fuzz_mime \
  ./lib/libglobal.a ./lib/libutil.a -ldb
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/global/fuzz_haproxy.o \
  -o $OUT/fuzz_haproxy ./lib/libglobal.a ./lib/libutil.a
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/util/fuzz_dict_regexp.o \
  -o $OUT/fuzz_dict_regexp ./lib/libutil.a
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./src/util/fuzz_dict_cidr.o \
  -o $OUT/fuzz_dict_cidr ./lib/libutil.a

# Package seed corpora
for harness in fuzz_dict_regexp fuzz_dict_cidr fuzz_haproxy; do
  if [ -d "$SRC/seeds/${harness}" ] && ls "$SRC/seeds/${harness}"/* >/dev/null 2>&1; then
    zip -j "$OUT/${harness}_seed_corpus.zip" "$SRC/seeds/${harness}"/*
  fi
done

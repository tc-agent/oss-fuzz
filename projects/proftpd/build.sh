#!/bin/bash -eu
# Copyright 2021 Google LLC.
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

cp tests/fuzzing/json_fuzzer.c $SRC/fuzzer.c
tests/fuzzing/oss_fuzz_build.sh

NEW_CC_FLAG="${CC} ${CFLAGS} -DHAVE_CONFIG_H -DLINUX -I. -I./include"

for harness in netacl_fuzzer logfmt_fuzzer ftpaccess_fuzzer cmd_fuzzer; do
  $NEW_CC_FLAG -c $SRC/${harness}.c -o ${harness}.o
  $CC $CXXFLAGS $LIB_FUZZING_ENGINE ${harness}.o -o $OUT/${harness} \
    src/scoreboard.o \
    lib/prbase.a \
    fuzz_lib.a \
    -L/src/proftpd/lib \
    -lcrypt -pthread
done

zip -j $OUT/netacl_fuzzer_seed_corpus.zip $SRC/netacl_seeds/*
zip -j $OUT/logfmt_fuzzer_seed_corpus.zip $SRC/logfmt_seeds/*
zip -j $OUT/ftpaccess_fuzzer_seed_corpus.zip $SRC/ftpaccess_seeds/*
zip -j $OUT/cmd_fuzzer_seed_corpus.zip $SRC/cmd_seeds/*

cp $SRC/ftpaccess_fuzzer.dict $OUT/ftpaccess_fuzzer.dict

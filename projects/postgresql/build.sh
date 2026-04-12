#!/bin/bash -eux
# Copyright 2020 Google Inc.
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
# Apply diff for fuzzers
cp -r $SRC/fuzzer src/backend/
git apply --ignore-space-change --ignore-whitespace  ../add_fuzzers.diff

# Change permission for fuzzers
useradd fuzzuser
chown -R fuzzuser .

cd bld

CC="" CXX="" CFLAGS="" CXXFLAGS="" su fuzzuser -c ../configure
cd src/backend/fuzzer
su fuzzuser -c "make -j10 createdb"
chown -R root .
mv temp/data .
cp -r data $OUT/
cd ../../..
cp -r tmp_install $OUT/
make clean

../configure
make -j$(nproc)

# Manually remove main function from main.c and recompile it
cd ../
git apply --ignore-space-change --ignore-whitespace  $SRC/main.diff
cd bld
$CC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -I./src/include -I./src/include/port -I../src/include -fPIC -c ../src/backend/main/main.c -o ./src/backend/main/main.o

# Package static library
cd src/backend
ar rcs libpostgres.a $(find . -name '*.o' | grep -v '^./fuzzer/')

cd fuzzer
make -j$(nproc) fuzzer
#if [ "$FUZZING_ENGINE" = "afl" ]
#then
rm protocol_fuzzer
#fi
cp *_fuzzer $OUT/
cp $SRC/postgresql_fuzzer_seed_corpus.zip $OUT/

#!/bin/bash -eu
# Copyright 2023 Google LLC
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

export CXXFLAGS="$CFLAGS"

# Register additional fuzz targets in the upstream fuzz/CMakeLists.txt
cat >> $SRC/wt/fuzz/CMakeLists.txt << 'EOF'

ADD_EXECUTABLE(fuzz-datetime fuzz-datetime.C)
ADD_EXECUTABLE(fuzz-utils    fuzz-utils.C)
ADD_EXECUTABLE(fuzz-xss      fuzz-xss.C)

TARGET_LINK_LIBRARIES(fuzz-datetime PRIVATE wt $ENV{LIB_FUZZING_ENGINE})
TARGET_LINK_LIBRARIES(fuzz-utils    PRIVATE wt $ENV{LIB_FUZZING_ENGINE})
TARGET_LINK_LIBRARIES(fuzz-xss      PRIVATE wt $ENV{LIB_FUZZING_ENGINE})
EOF

mkdir -p mybuild

pushd mybuild/
cmake -DSHARED_LIBS=OFF -DBUILD_FUZZ=ON -DBoost_USE_STATIC_LIBS=ON ../.
make -j$(nproc) --ignore-errors
cp fuzz/fuzz-* $OUT/
popd

cp fuzz/*zip $OUT/

for h in fuzz-datetime fuzz-utils fuzz-xss; do
  zip -j $OUT/${h}_seed_corpus.zip $SRC/seeds/$h/*
done

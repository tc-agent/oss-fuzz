#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Copy additional harnesses into the upstream oss-fuzz test directory before
# running boot.sh/configure so automake picks them up.
cp "$SRC/ovsdb_schema_target.c" \
   "$SRC/conntrack_target.c" \
   "$SRC/openvswitch/tests/oss-fuzz/"

# Append the new targets to the upstream automake fragment.  This must happen
# before boot.sh re-runs automake so the generated Makefile includes them.
#
# We avoid OSS_FUZZ_TARGETS += because EXTRA_PROGRAMS is already expanded from
# that variable earlier in the fragment; extending via EXTRA_PROGRAMS and a
# supplemental oss-fuzz-targets prerequisite rule is safer.
cat >> "$SRC/openvswitch/tests/oss-fuzz/automake.mk" << 'EOF'

# Additional fuzz targets added by OSS-Fuzz integration.
EXTRA_PROGRAMS += \
	tests/oss-fuzz/ovsdb_schema_target \
	tests/oss-fuzz/conntrack_target

# Extend oss-fuzz-targets to include the new harnesses.
oss-fuzz-targets: tests/oss-fuzz/ovsdb_schema_target tests/oss-fuzz/conntrack_target

tests_oss_fuzz_ovsdb_schema_target_SOURCES = \
	tests/oss-fuzz/ovsdb_schema_target.c \
	tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_ovsdb_schema_target_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la
tests_oss_fuzz_ovsdb_schema_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++

tests_oss_fuzz_conntrack_target_SOURCES = \
	tests/oss-fuzz/conntrack_target.c \
	tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_conntrack_target_LDADD = lib/libopenvswitch.la
tests_oss_fuzz_conntrack_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++
EOF

./boot.sh && HAVE_UNWIND=no ./configure --enable-ndebug && make -j$(nproc) && make oss-fuzz-targets

cp $SRC/openvswitch/tests/oss-fuzz/config/*.options $OUT/
cp $SRC/openvswitch/tests/oss-fuzz/config/*.dict $OUT/
wget -O $OUT/json.dict https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/json.dict

# Options files for the new harnesses (shipped alongside build.sh).
cp $SRC/ovsdb_schema_target.options $SRC/conntrack_target.options $OUT/

for file in $SRC/openvswitch/tests/oss-fuzz/*_target;
do
       cp $file $OUT/
       name=$(basename $file)
       corp_name=$(basename $file _target)
       corp_dir=$SRC/ovs-fuzzing-corpus/${corp_name}_seed_corpus
       if [ -d ${corp_dir} ]; then
           zip -rq $OUT/${name}_seed_corpus ${corp_dir}
       fi
       # Also check for seed corpora shipped with our harnesses.
       local_corp=$SRC/seeds/${corp_name}
       if [ -d "${local_corp}" ]; then
           zip -rq $OUT/${name}_seed_corpus ${local_corp}
       fi
done

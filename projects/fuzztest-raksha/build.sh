#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# Raksha depends on rules_proto_grpc 4.1.1 which emits the `nocopts` cc_library
# attribute removed in Bazel 7, and WORKSPACE which Bazel 9+ hides behind bzlmod.
export USE_BAZEL_VERSION=6.5.0

# Extend with oss-fuzz settings. To be upsteamed?
cd $SRC/raksha
git apply  --ignore-space-change --ignore-whitespace $SRC/raksha-fuzztest.diff

# Raksha enables -Werror. The pinned abseil uses __is_trivially_relocatable which
# is deprecated in the base-builder's Clang 22, causing -Wdeprecated-builtins errors.
echo "build --cxxopt=-Wno-error=deprecated-builtins" >> .bazelrc

# The pinned fuzztest version's setup_configs does not link the fuzzing engine
# for OSS-Fuzz builds. Add the missing linkopts that the current fuzztest
# setup_configs.sh generates (fuzzer runtime + UBSan runtime).
ARCH=$(uname -m)
FUZZER_LIB=$(find /usr -name "libclang_rt.fuzzer_no_main*" 2>/dev/null | grep "$ARCH" | grep '\.a$' | head -1)
if [ -z "$FUZZER_LIB" ]; then
  echo "ERROR: Could not find libclang_rt.fuzzer_no_main for $ARCH" >&2
  exit 1
fi
echo "build:oss-fuzz --linkopt=$FUZZER_LIB" >> .bazelrc
if [ "${SANITIZER:-}" = "undefined" ]; then
  UBSAN_LIB=$(find /usr -name "libclang_rt.ubsan_standalone_cxx*" 2>/dev/null | grep "$ARCH" | grep '\.a$' | head -1)
  [ -n "$UBSAN_LIB" ] && echo "build:oss-fuzz --linkopt=$UBSAN_LIB" >> .bazelrc
fi

# Compile gfuzztests
export FUZZTEST_TARGET_FOLDER="//src/..."
compile_fuzztests.sh

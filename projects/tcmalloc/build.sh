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

# tcmalloc migrated from cc_fuzz_test (rules_fuzzing) to FuzzTest (FUZZ_TEST
# macro with fuzztest_gtest_main). Use compile_fuzztests.sh which is the
# standard OSS-Fuzz builder for FuzzTest projects.

# Pin Bazel 8: Bazel 9's bazel_tools requires rules_swift 3.1.2 (compat level 3)
# which conflicts with flatbuffers' transitive dep on rules_swift 2.x (compat
# level 2). Upstream fix: https://github.com/google/flatbuffers/pull/8909
export USE_BAZEL_VERSION=8.2.1

# Stub out libpfm (transitive dep: google_benchmark -> libpfm). Its download
# URL (netcologne.dl.sourceforge.net) does not resolve in GitHub Actions. Fuzz
# targets never use hardware perf counters, so a no-op stub is safe.
mkdir -p /tmp/fake_libpfm
cat > /tmp/fake_libpfm/BUILD.bazel << 'STUBEOF'
package(default_visibility = ["//visibility:public"])
cc_library(name = "libpfm")
cc_library(name = "pfm")
STUBEOF
cat > /tmp/fake_libpfm/MODULE.bazel << 'STUBEOF'
module(name = "libpfm", version = "4.11.0")
STUBEOF
echo "common --override_repository=libpfm+=/tmp/fake_libpfm" >> /etc/bazel.bazelrc

export FUZZTEST_TARGET_FOLDER="//tcmalloc/..."

# FuzzTest's --list_fuzz_tests outputs "[*] Fuzz test: SuiteName.TestName" lines.
# compile_fuzztests.sh splits on whitespace, creating bad entries for "[*]", "Fuzz",
# "test:" etc. Patch it to skip entries without a dot (valid names are Suite.Test).
sed -i '/for fuzz_entrypoint in \$FUZZ_TESTS/a\    echo "$fuzz_entrypoint" | grep -q "\\." || continue' \
  "$(which compile_fuzztests.sh)"

compile_fuzztests.sh

#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# Copy kea-specific fuzzers/dict/seeds from ada-fuzzers
cp -r $SRC/ada-fuzzers/projects/kea $SRC/kea-fuzzer

# Remove the rest of ada-fuzzers: Fuzz Introspector scans the entire $SRC
# tree, and ada-fuzzers contains harnesses for unrelated projects (llvm, gpsd,
# etc.) that inflate the analysis scope.
rm -rf $SRC/ada-fuzzers

# Run build script
$SRC/kea-fuzzer/build.sh

# For introspector builds: remove kea test directories after compilation.
# kea has ~2800 source files; a large fraction are unit test files that
# Fuzz Introspector parses with tree-sitter post-build, causing a timeout.
# Tests have already been compiled into the bitcode, so removing the source
# files only affects the post-build source analysis, not the LLVM IR.
if [ "$SANITIZER" = "introspector" ]; then
  find $SRC/kea -name "tests" -type d -exec rm -rf {} + 2>/dev/null || true
fi

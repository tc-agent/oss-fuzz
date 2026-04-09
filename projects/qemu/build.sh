#!/bin/sh -e
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

cd $SRC/qemu/
$SRC/qemu/scripts/oss-fuzz/build.sh

# Generate minimal seed corpus for each fuzz target.
# The coverage build falls back to seed corpus when the ClusterFuzz
# corpus backup is unavailable (e.g. for newly integrated targets or
# when the backup pipeline is broken).
for target in $OUT/qemu-fuzz-i386-target-*; do
  target_name=$(basename "$target")
  [ -x "$target" ] || continue
  [ -f "$OUT/${target_name}_seed_corpus.zip" ] && continue
  seed_dir=$(mktemp -d)
  printf '\x00\x00\x00\x00' > "$seed_dir/null_seed"
  (cd "$seed_dir" && zip -q "$OUT/${target_name}_seed_corpus.zip" null_seed)
  rm -rf "$seed_dir"
done

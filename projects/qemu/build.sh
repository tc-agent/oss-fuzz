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

# Remove stale fuzz target binaries from a previous build so that
# the upstream `ln` calls do not fail with "File exists" when $OUT
# is reused between builds (e.g. Fuzz Verify CI).
find "$OUT" -maxdepth 1 -name 'qemu-fuzz-i386*' \
    ! -name '*_seed_corpus.zip' ! -name '*.options' -type f -delete

$SRC/qemu/scripts/oss-fuzz/build.sh

# Generate a minimal seed corpus for each fuzz target.
# Coverage builds use seed corpus as fallback when ClusterFuzz corpus backups
# are unavailable (e.g. when corpus pruning has not completed successfully).
python3 - <<'EOF'
import os, zipfile

out = os.environ["OUT"]
for fname in sorted(os.listdir(out)):
    if not fname.startswith("qemu-fuzz-i386-target-"):
        continue
    if fname.endswith("_seed_corpus.zip"):
        continue
    if not os.path.isfile(os.path.join(out, fname)):
        continue
    seed_zip = os.path.join(out, fname + "_seed_corpus.zip")
    if os.path.exists(seed_zip):
        continue
    with zipfile.ZipFile(seed_zip, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("seed", b"\x00\x00\x00\x00")
EOF

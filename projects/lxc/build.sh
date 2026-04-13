#!/bin/bash -e
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

# Copy new harnesses into the source tree so oss-fuzz.sh picks them up.
cp "$SRC/fuzz-lxc-idmaps.c"     src/tests/
cp "$SRC/fuzz-lxc-config-net.c" src/tests/

# Patch src/tests/meson.build to add build targets for the new harnesses.
python3 - <<'EOF'
path = "src/tests/meson.build"
with open(path) as f:
    content = f.read()

new_targets = """

    test_programs += executable(
        'fuzz-lxc-idmaps',
        files('fuzz-lxc-idmaps.c') + include_sources + netns_ifaddrs_sources,
        include_directories: liblxc_includes,
        dependencies: [fuzzing_engine, oss_fuzz_dependencies],
        link_with: [liblxc_static],
        install: false,
        install_dir: bindir)

    test_programs += executable(
        'fuzz-lxc-config-net',
        files('fuzz-lxc-config-net.c') + include_sources + netns_ifaddrs_sources,
        include_directories: liblxc_includes,
        dependencies: [fuzzing_engine, oss_fuzz_dependencies],
        link_with: [liblxc_static],
        install: false,
        install_dir: bindir)
"""

# Insert before the closing "endif" of the want_oss_fuzz block.
# Target the specific closing of the fuzz-lxc-define-load target, which is
# the last entry before the endif that closes the want_oss_fuzz block.
marker = (
    "        'fuzz-lxc-define-load',\n"
    "        files('fuzz-lxc-define-load.c') + include_sources + netns_ifaddrs_sources,\n"
    "        include_directories: liblxc_includes,\n"
    "        dependencies: [fuzzing_engine, oss_fuzz_dependencies],\n"
    "        link_with: [liblxc_static],\n"
    "        install: false,\n"
    "        install_dir: bindir)\nendif"
)
replacement = (
    "        'fuzz-lxc-define-load',\n"
    "        files('fuzz-lxc-define-load.c') + include_sources + netns_ifaddrs_sources,\n"
    "        include_directories: liblxc_includes,\n"
    "        dependencies: [fuzzing_engine, oss_fuzz_dependencies],\n"
    "        link_with: [liblxc_static],\n"
    "        install: false,\n"
    "        install_dir: bindir)"
    + new_targets +
    "endif"
)
assert marker in content, "Pattern not found in meson.build — upstream may have changed"
content = content.replace(marker, replacement, 1)

with open(path, "w") as f:
    f.write(content)

print("meson.build patched OK")
EOF

# Build using the upstream oss-fuzz script (handles meson setup + ninja).
export CFLAGS="${CFLAGS} -Wno-error=backend-plugin"
src/tests/oss-fuzz.sh

# Package seed corpora for the new harnesses.
if [ -d "$SRC/fuzz-lxc-idmaps_seed_corpus" ]; then
    zip -j "$OUT/fuzz-lxc-idmaps_seed_corpus.zip" "$SRC/fuzz-lxc-idmaps_seed_corpus"/*
fi
if [ -d "$SRC/fuzz-lxc-config-net_seed_corpus" ]; then
    zip -j "$OUT/fuzz-lxc-config-net_seed_corpus.zip" "$SRC/fuzz-lxc-config-net_seed_corpus"/*
fi

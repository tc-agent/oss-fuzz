#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/u-boot

# 0. Copy custom harnesses into the source tree.
# They live at $SRC/ (not $SRC/u-boot/) so they survive local-source mounts
# in the upstream CI (which mounts the PR checkout over $SRC/u-boot/).
cp $SRC/efi_load_image.c $SRC/u-boot/test/fuzz/
cp $SRC/fit_image_load.c $SRC/u-boot/test/fuzz/
cp $SRC/image_decomp.c $SRC/u-boot/test/fuzz/
cp $SRC/fuzz_fs.c $SRC/u-boot/test/fuzz/

# 1. Patch u-boot source
git apply $SRC/oss-fuzz.patch

# 2. Configure: sandbox + fuzz + all fuzzer target dependencies
make sandbox_defconfig CC="$CC" HOSTCC="$CC"
./scripts/config --enable CONFIG_FUZZ
./scripts/config --enable CONFIG_DM_FUZZING_ENGINE
./scripts/config --enable CONFIG_FUZZING_ENGINE_SANDBOX
./scripts/config --disable CONFIG_EFI_CAPSULE_AUTHENTICATE
./scripts/config --disable CONFIG_LTO
./scripts/config --disable CONFIG_OF_SEPARATE
./scripts/config --enable CONFIG_OF_EMBED
./scripts/config --set-str CONFIG_DEFAULT_DEVICE_TREE "test"
# Decompressors
./scripts/config --enable CONFIG_GZIP
./scripts/config --enable CONFIG_BZIP2
./scripts/config --enable CONFIG_LZMA
./scripts/config --enable CONFIG_LZO
./scripts/config --enable CONFIG_LZ4
./scripts/config --enable CONFIG_ZSTD
# Filesystems
./scripts/config --enable CONFIG_FS_BTRFS
./scripts/config --enable CONFIG_CMD_BTRFS
./scripts/config --enable CONFIG_CMD_FAT
./scripts/config --enable CONFIG_CMD_EXT4
./scripts/config --enable CONFIG_CMD_SQUASHFS
make olddefconfig CC="$CC" HOSTCC="$CC"

# 3. Build u-boot sandbox
#    NO_PYTHON=1 skips pylibfdt (_libfdt.so) meaning no shared libraries.
#    CONFIG_BINMAN= prevents binman (needs pylibfdt) from running.
#    -fintegrated-as avoids clang/gas assembler incompatibility.
#    KCFLAGS passes $CFLAGS (which the OSS-Fuzz compile script populates
#    with sanitizer and coverage flags) through to both compilation and
#    the link command (the patch adds $(KCFLAGS) to cmd_u-boot__).
make -j$(nproc) CROSS_COMPILE="" CC="$CC" HOSTCC="$CC" NO_PYTHON=1 \
    CONFIG_BINMAN= KCFLAGS="$CFLAGS -fintegrated-as"

# 4. Install all fuzzers (same binary, different names)
FUZZERS="
    fuzz_efi_load_image
    fuzz_fit_image_load
    fuzz_image_decomp
    fuzz_fs
"

for fuzzer in $FUZZERS; do
    cp u-boot $OUT/$fuzzer
    # fuzz_fs needs a larger max_len so 80KB+ filesystem seeds aren't
    # truncated by libFuzzer's dynamic length growth.
    if [ "$fuzzer" = "fuzz_fs" ]; then
        EXTRA_LIBFUZZER="max_len=131072"
    else
        EXTRA_LIBFUZZER=""
    fi
    cat > $OUT/$fuzzer.options <<EOF
[libfuzzer]
detect_leaks=0
$EXTRA_LIBFUZZER
[asan]
detect_leaks=0
EOF
done

# Package the filesystem seed corpus alongside fuzz_fs. base-runner unzips
# this into the corpus dir on each fuzzer start, so seeds survive
# libFuzzer's corpus minimisation and re-seed every run.
(cd $SRC/seeds_fuzz_fs && zip -qr $OUT/fuzz_fs_seed_corpus.zip .)


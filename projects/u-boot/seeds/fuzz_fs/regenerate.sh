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
# Regenerates the binary seed corpus for the fuzz_fs harness. Run from any
# directory; output goes to the directory holding this script. Requires
# dosfstools, e2fsprogs, btrfs-progs, squashfs-tools and mtools.
#
#     bash regenerate.sh
#
# All produced images are <= 128 KiB so they fit fuzz_fs's max_len=131072.

OUT=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

# A small content tree to populate the "with files" variants.
mkdir -p $WORK/src/dir1
echo hello > $WORK/src/file_a.txt
echo world > $WORK/src/dir1/file_b.txt

# FAT12 / FAT16 (empty)
dd if=/dev/zero of=$OUT/fat12.img bs=512 count=128 status=none
mkfs.fat -F 12 $OUT/fat12.img >/dev/null
dd if=/dev/zero of=$OUT/fat16.img bs=512 count=2048 status=none
mkfs.fat -F 16 $OUT/fat16.img >/dev/null
dd if=$OUT/fat16.img of=$OUT/fat16.img.tmp bs=1024 count=128 status=none
mv $OUT/fat16.img.tmp $OUT/fat16.img

# FAT16 with files (mtools — no mount required)
dd if=/dev/zero of=$WORK/fat16_files.img bs=512 count=8192 status=none
mkfs.fat -F 16 $WORK/fat16_files.img >/dev/null
mcopy -i $WORK/fat16_files.img -s $WORK/src/* ::
dd if=$WORK/fat16_files.img of=$OUT/fat16_files.img bs=1024 count=128 status=none

# ext4 (empty + with files)
dd if=/dev/zero of=$WORK/ext4.img bs=1024 count=2048 status=none
mkfs.ext4 -q -F $WORK/ext4.img 2>/dev/null
dd if=$WORK/ext4.img of=$OUT/ext4.img bs=1024 count=128 status=none
dd if=/dev/zero of=$WORK/ext4_files.img bs=1024 count=2048 status=none
mke2fs -t ext4 -q -F -d $WORK/src $WORK/ext4_files.img
dd if=$WORK/ext4_files.img of=$OUT/ext4_files.img bs=1024 count=128 status=none

# SquashFS variants
mksquashfs $WORK/src $OUT/squashfs.img -noappend -no-progress -quiet
for comp in gzip xz lzo zstd lz4; do
    rm -f $OUT/sqfs_$comp.img
    mksquashfs $WORK/src $OUT/sqfs_$comp.img \
        -comp $comp -noappend -no-progress -quiet
done

# btrfs (empty + with files; primary superblock lives at offset 65536+0x40)
truncate -s 128M $WORK/btrfs.img
mkfs.btrfs -f -q $WORK/btrfs.img
dd if=$WORK/btrfs.img of=$OUT/btrfs_80k.img bs=1024 count=80 status=none

truncate -s 128M $WORK/btrfs_files.img
mkfs.btrfs -f -q --rootdir $WORK/src $WORK/btrfs_files.img
dd if=$WORK/btrfs_files.img of=$OUT/btrfs_files_96k.img bs=1024 count=96 status=none
dd if=$WORK/btrfs_files.img of=$OUT/btrfs_files_128k.img bs=1024 count=128 status=none

ls -la $OUT/*.img

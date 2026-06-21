#!/usr/bin/env python3
# Copyright 2026 Google Inc.
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
"""Generate seed corpora for the new git fuzz harnesses.

Run from projects/git/ as: python3 seeds/gen_seeds.py
"""
from pathlib import Path

ROOT = Path(__file__).parent  # seeds/
ZHASH = "0" * 40  # placeholder SHA-1 hex
ZRAW = b"\x00" * 20  # placeholder SHA-1 raw bytes


def w(name: str, data: bytes) -> None:
    p = ROOT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


# ---- fuzz-parse-commit ----
COMMIT_MIN = (
    f"tree {ZHASH}\n"
    f"author A U Thor <a@u.example> 1700000000 +0000\n"
    f"committer C O Mitter <c@o.example> 1700000000 +0000\n"
    f"\n"
    f"initial commit\n"
).encode()

COMMIT_PARENT = (
    f"tree {ZHASH}\n"
    f"parent {ZHASH}\n"
    f"author A U Thor <a@u.example> 1700000000 +0000\n"
    f"committer C O Mitter <c@o.example> 1700000000 +0000\n"
    f"\n"
    f"second commit\n"
).encode()

w("fuzz-parse-commit/min", COMMIT_MIN)
w("fuzz-parse-commit/parent", COMMIT_PARENT)


# ---- fuzz-parse-tag ----
TAG_COMMIT = (
    f"object {ZHASH}\n"
    f"type commit\n"
    f"tag v1.0\n"
    f"tagger A U Thor <a@u.example> 1700000000 +0000\n"
    f"\n"
    f"release v1.0\n"
).encode()

TAG_TREE = (
    f"object {ZHASH}\n"
    f"type tree\n"
    f"tag tree-tag\n"
    f"tagger A U Thor <a@u.example> 1700000000 +0000\n"
    f"\n"
    f"tag of a tree\n"
).encode()

TAG_BLOB = (
    f"object {ZHASH}\n"
    f"type blob\n"
    f"tag blob-tag\n"
    f"tagger A U Thor <a@u.example> 1700000000 +0000\n"
    f"\n"
    f"tag of a blob\n"
).encode()

w("fuzz-parse-tag/commit", TAG_COMMIT)
w("fuzz-parse-tag/tree", TAG_TREE)
w("fuzz-parse-tag/blob", TAG_BLOB)


# ---- fuzz-tree-walk ----
def tree_entry(mode: str, name: str, raw_oid: bytes = ZRAW) -> bytes:
    return mode.encode() + b" " + name.encode() + b"\x00" + raw_oid


w("fuzz-tree-walk/single-blob", tree_entry("100644", "file.txt"))
w(
    "fuzz-tree-walk/blob-and-dir",
    tree_entry("100644", "a.txt") + tree_entry("40000", "subdir"),
)
w(
    "fuzz-tree-walk/multi",
    tree_entry("100644", "a") + tree_entry("100644", "b") + tree_entry("100644", "c"),
)
w(
    "fuzz-tree-walk/special-modes",
    tree_entry("100755", "exe")
    + tree_entry("120000", "link")
    + tree_entry("160000", "submod"),
)


# ---- fuzz-fsck ----
# First byte selects type: 0=commit, 1=tree, 2=blob, 3=tag (per harness)
w("fuzz-fsck/commit", b"\x00" + COMMIT_MIN)
w("fuzz-fsck/tree", b"\x01" + tree_entry("100644", "file.txt"))
w("fuzz-fsck/blob", b"\x02hello world")
w("fuzz-fsck/tag", b"\x03" + TAG_COMMIT)


# ---- fuzz-refname ----
for name, content in [
    ("tag", b"refs/tags/v1.0"),
    ("remote", b"refs/remotes/origin/main"),
    ("head", b"HEAD"),
    ("nested", b"refs/heads/feature/sub/topic"),
    ("stash", b"refs/stash"),
    ("traversal", b"refs/heads/../evil"),
    ("dotlock", b"refs/heads/foo.lock"),
    ("glob", b"refs/heads/*"),
]:
    w(f"fuzz-refname/{name}", content)


print("Wrote seeds under", ROOT)

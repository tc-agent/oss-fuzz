#!/bin/bash -eu
# Copyright 2020 Google LLC
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

# Ensure libevent can be found
export PKG_CONFIG_PATH="/usr/local/lib/"

# Copy new harnesses into the source tree and register them in Makefile.am.
cp -v "$SRC/colour-fuzzer.c" "$SRC/tmux/fuzz/"
cp -v "$SRC/colour-fuzzer.options" "$SRC/tmux/fuzz/"
cp -v "$SRC/colour-fuzzer.dict" "$SRC/tmux/fuzz/"
cp -v "$SRC/key-string-fuzzer.c" "$SRC/tmux/fuzz/"
cp -v "$SRC/key-string-fuzzer.options" "$SRC/tmux/fuzz/"
cp -v "$SRC/key-string-fuzzer.dict" "$SRC/tmux/fuzz/"

# Patch Makefile.am to add the new fuzz targets (idempotent: skip if already present).
python3 - <<'PYEOF'
with open("Makefile.am") as f:
    content = f.read()

if "fuzz/colour-fuzzer" in content:
    print("Makefile.am already has colour-fuzzer — skipping patch")
else:
    old = """\
check_PROGRAMS = \\
\tfuzz/input-fuzzer \\
\tfuzz/cmd-parse-fuzzer \\
\tfuzz/format-fuzzer \\
\tfuzz/style-fuzzer
fuzz_input_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_input_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_cmd_parse_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_cmd_parse_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_format_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_format_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_style_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_style_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)"""

    new = """\
check_PROGRAMS = \\
\tfuzz/input-fuzzer \\
\tfuzz/cmd-parse-fuzzer \\
\tfuzz/format-fuzzer \\
\tfuzz/style-fuzzer \\
\tfuzz/colour-fuzzer \\
\tfuzz/key-string-fuzzer
fuzz_input_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_input_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_cmd_parse_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_cmd_parse_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_format_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_format_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_style_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_style_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_colour_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_colour_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)
fuzz_key_string_fuzzer_LDFLAGS = $(FUZZING_LIBS)
fuzz_key_string_fuzzer_LDADD = $(LDADD) $(tmux_OBJECTS)"""

    if old not in content:
        raise SystemExit("Makefile.am patch anchor not found — upstream changed?")

    content = content.replace(old, new, 1)
    with open("Makefile.am", "w") as f:
        f.write(content)
    print("Makefile.am patched OK")
PYEOF

./autogen.sh
./configure \
    --enable-fuzzing \
    FUZZING_LIBS="${LIB_FUZZING_ENGINE} -lc++" \
    LIBEVENT_LIBS="-Wl,-Bstatic -levent -Wl,-Bdynamic" \
    LIBTINFO_LIBS=" -l:libtinfo.a "

make -j"$(nproc)" check
find "${SRC}/tmux/fuzz/" -name '*-fuzzer' -exec cp -v '{}' "${OUT}"/ \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.options' -exec cp -v '{}' "${OUT}"/ \;
find "${SRC}/tmux/fuzz/" -name '*-fuzzer.dict' -exec cp -v '{}' "${OUT}"/ \;

MAXLEN=$(grep -Po 'max_len\s+=\s+\K\d+' "${OUT}/input-fuzzer.options")

if [ ! -d "${WORK}/fuzzing_corpus" ]; then
    mkdir "${WORK}/fuzzing_corpus"
    cd "${WORK}/fuzzing_corpus"
    bash "${SRC}/tmux/tools/24-bit-color.sh" | \
        split -a4 -db$MAXLEN - 24-bit-color.out.
    perl "${SRC}/tmux/tools/256colors.pl" | \
        split -a4 -db$MAXLEN - 256colors.out.
    cat "${SRC}/tmux/tools/UTF-8-demo.txt" | \
        split -a4 -db$MAXLEN - UTF-8-demo.txt.
    cat "${SRC}/tmux-fuzzing-corpus/alacritty"/* | \
        split -a4 -db$MAXLEN - alacritty.
    cat "${SRC}/tmux-fuzzing-corpus/esctest"/* | \
        split -a4 -db$MAXLEN - esctest.
    cat "${SRC}/tmux-fuzzing-corpus/iterm2"/* | \
        split -a5 -db$MAXLEN - iterm2.
    zip -q -j -r "${OUT}/input-fuzzer_seed_corpus.zip" \
        "${WORK}/fuzzing_corpus/"
fi

# Seed corpora for all non-input fuzzers
zip -q -j -r "${OUT}/format-fuzzer_seed_corpus.zip" \
    "${SRC}/format-fuzzer-seeds/"
zip -q -j -r "${OUT}/style-fuzzer_seed_corpus.zip" \
    "${SRC}/style-fuzzer-seeds/"
zip -q -j -r "${OUT}/cmd-parse-fuzzer_seed_corpus.zip" \
    "${SRC}/cmd-parse-fuzzer-seeds/"
zip -q -j -r "${OUT}/colour-fuzzer_seed_corpus.zip" \
    "${SRC}/colour-fuzzer-seeds/"
zip -q -j -r "${OUT}/key-string-fuzzer_seed_corpus.zip" \
    "${SRC}/key-string-fuzzer-seeds/"

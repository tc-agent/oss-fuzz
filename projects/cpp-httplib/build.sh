#!/bin/bash -eu
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

# Build fuzz targets specified  in test/Makefile.
cd test/fuzzing && make -j$(nproc) all

# Upstream Makefile only zips seed corpora for server_fuzzer and client_fuzzer.
# Provide the missing zips so url_parser_fuzzer and header_parser_fuzzer have
# a non-empty corpus when ClusterFuzz backups are unavailable.
for fuzzer in url_parser_fuzzer header_parser_fuzzer; do
  [ -f "${fuzzer}_seed_corpus.zip" ] || zip -q -r "${fuzzer}_seed_corpus.zip" corpus
done

# Copy the fuzzer executables, zip-ed corpora, option and dictionary files to $OUT.
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'          # Copy fuzz-target.
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'     # Copy dictionaries.
find . -name '*_fuzzer_seed_corpus.zip' -exec cp -v '{}' $OUT ';' # Copy seed corpora.

#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

cd 'tests'

export LDO=$CXX
export LDFLAGS="$CXXFLAGS $LIB_FUZZING_ENGINE"
export CFLAGS="$CFLAGS -MMD"

if [[ "$ARCHITECTURE" == "i386" ]]; then
	# Force static link
	rm -v /lib/i386-linux-gnu/libcrypto.so* || :
fi

# Specific to hostap's rules.include: set empty, as we directly set required
# sanitizer flags in CFLAGS and LDFLAGS (above).
export FUZZ_FLAGS=

# ---------------------------------------------------------------------------
# Enrich the example seed corpora before they are zipped. The upstream
# */corpus directories ship only 1-5 tiny example inputs each, so a short
# fuzzing run barely reaches past the outer parsers. Two additions:
#   1. Structured protocol seeds generated from readable code (gen_seeds.py).
#   2. DER encodings of the certificates / keys / PKCS structures already
#      present in tests/hwsim/auth_serv, which exercise the X.509 / ASN.1 /
#      bignum / RSA / PKCS parsers far more thoroughly than the 2 example
#      inputs shipped for the x509 / asn1 targets.
# Existing example inputs are kept; only extra "g-"/"der-" files are added.
# ---------------------------------------------------------------------------
python3 "$SRC/seeds/gen_seeds.py" "$PWD/fuzzing" || true

add_der() {
  # add_der <dest-corpus-dir> <name> <file-producing-command...>
  local dest="$1"; local name="$2"; shift 2
  mkdir -p "$dest"
  if "$@" > "$dest/$name" 2>/dev/null && [[ -s "$dest/$name" ]]; then
    :
  else
    rm -f "$dest/$name"
  fi
}

X509_C="$PWD/fuzzing/x509/corpus"
ASN1_C="$PWD/fuzzing/asn1/corpus"
CERTDIR="$PWD/hwsim/auth_serv"
if [[ -d "$CERTDIR" ]]; then
  i=0
  for f in "$CERTDIR"/*; do
    [[ -f "$f" ]] || continue
    b=$(basename "$f")
    i=$((i + 1))
    # X.509 certificate (PEM or DER) -> DER : valid input for both targets.
    add_der "$X509_C" "der-cert-$i" \
      openssl x509 -in "$f" -inform PEM -outform DER
    [[ -s "$X509_C/der-cert-$i" ]] || \
      add_der "$X509_C" "der-cert-$i" \
        openssl x509 -in "$f" -inform DER -outform DER
    if [[ -s "$X509_C/der-cert-$i" ]]; then
      cp "$X509_C/der-cert-$i" "$ASN1_C/der-cert-$i" 2>/dev/null || true
    fi
    # CSR / CRL / private key / params -> DER : extra ASN.1 structures.
    add_der "$ASN1_C" "der-csr-$i"  openssl req  -in "$f" -outform DER
    add_der "$ASN1_C" "der-crl-$i"  openssl crl  -in "$f" -outform DER
    add_der "$ASN1_C" "der-key-$i"  openssl pkcs8 -topk8 -nocrypt \
      -in "$f" -outform DER
    case "$b" in
      *.der|*.der-invalid|*.p12|*.pkcs12|*.pkcs8|*.pkcs5v15)
        cp "$f" "$ASN1_C/der-raw-$i" 2>/dev/null || true ;;
    esac
  done
fi

for target in fuzzing/*; do
  [[ -d "$target" ]] || continue

  (
    cd "$target"
    make clean

    if [[ "$target" == "fuzzing/tls-server" ]]; then
      export CFLAGS="$CFLAGS -DCERTDIR='\"hwsim/auth_serv/\"'"
    fi

    make -j$(nproc) V=1 LIBFUZZER=y
    mv -v "${target##*/}" "${OUT}/"

    if [[ -d 'corpus' ]]; then
      (cd 'corpus' && zip "${OUT}/${target##*/}_seed_corpus.zip" *)
    fi
  )
done

# Copy required data.
cp -a "hwsim" "${OUT}/"

#!/bin/bash -eu
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

BASE=${SRC}/openvpn/src/openvpn

apply_sed_changes() {
  sed -i 's/read(/fuzz_read(/g' ${BASE}/console_systemd.c
  sed -i 's/fgets(/fuzz_fgets(/g' ${BASE}/console_builtin.c
  sed -i 's/fgets(/fuzz_fgets(/g' ${BASE}/misc.c
  sed -i 's/#include "forward.h"/#include "fuzz_header.h"\n#include "forward.h"/g' ${BASE}/proxy.c
  sed -i 's/openvpn_select(/fuzz_select(/g' ${BASE}/proxy.c
  sed -i 's/openvpn_send(/fuzz_send(/g' ${BASE}/proxy.c
  sed -i 's/recv(/fuzz_recv(/g' ${BASE}/proxy.c
  sed -i 's/isatty/fuzz_isatty/g' ${BASE}/console_builtin.c

  sed -i 's/fopen/fuzz_fopen/g' ${BASE}/console_builtin.c
  sed -i 's/fclose/fuzz_fclose/g' ${BASE}/console_builtin.c

  sed -i 's/sendto/fuzz_sendto/g' ${BASE}/socket.h
  sed -i 's/#include "misc.h"/#include "misc.h"\nextern size_t fuzz_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);/g' ${BASE}/socket.h

  sed -i 's/fp = (flags/fp = stdout;\n\/\//g' ${BASE}/error.c

  sed -i 's/crypto_msg(M_FATAL/crypto_msg(M_WARN/g' ${BASE}/crypto_openssl.c
  sed -i 's/msg(M_FATAL, \"Cipher/return;msg(M_FATAL, \"Cipher/g' ${BASE}/crypto.c
  sed -i 's/msg(M_FATAL/msg(M_WARN/g' ${BASE}/crypto.c

  # fuzz_options drives read_config_string() with attacker-controlled input;
  # demoting these fatal messages to warnings stops the parser from killing
  # the fuzzer process on routine bad configs without disabling sanitizer
  # checks. The setjmp safety net stays in place for paths missed here.
  sed -i 's/msg(M_FATAL/msg(M_WARN/g; s/msg(M_USAGE/msg(M_WARN/g' ${BASE}/options.c
  sed -i 's/msg(M_FATAL/msg(M_WARN/g; s/msg(M_USAGE/msg(M_WARN/g' ${BASE}/options_parse.c
  sed -i 's/msg(M_FATAL/msg(M_WARN/g; s/msg(M_USAGE/msg(M_WARN/g' ${BASE}/options_util.c
  sed -i 's/msg(M_FATAL/msg(M_WARN/g; s/msg(M_USAGE/msg(M_WARN/g' ${BASE}/buffer.c

  sed -i 's/= write/= fuzz_write/g' ${BASE}/packet_id.c

  # Hook openvpn_exit() so M_FATAL/M_USAGE paths in fuzz harnesses can
  # longjmp out instead of killing the process. The fuzz_in_test flag is
  # only set by fuzz_options; other harnesses leave it 0 and behave as
  # before. Provided as weak globals in fake_fuzz_header.h (default to a
  # plain exit) and overridden strongly in fuzz_options.c.
  sed -i 's|^    exit(status);$|    if (fuzz_in_test) { fuzz_exit_longjmp(status); }\n    exit(status);|' ${BASE}/error.c
  # Free x_msg_va's local gc_arena before longjmping out, otherwise its
  # ~10 KB message buffer leaks once per fuzz iteration. The M_USAGE_SMALL
  # path goes through usage_small() (in options.c) before reaching
  # openvpn_exit, so we intercept it the same way.
  sed -i 's|^        openvpn_exit(OPENVPN_EXIT_STATUS_ERROR); /\* exit point \*/$|        gc_free(\&gc); openvpn_exit(OPENVPN_EXIT_STATUS_ERROR); /* exit point */|' ${BASE}/error.c
  sed -i 's|^        usage_small();$|        gc_free(\&gc); usage_small();|' ${BASE}/error.c
  sed -i -z 's|void\nopenvpn_exit(const int status)|__attribute__((weak)) int fuzz_in_test = 0;\n__attribute__((weak)) void fuzz_exit_longjmp(int status) { (void)status; }\nvoid\nopenvpn_exit(const int status)|' ${BASE}/error.c
}

# Changes in the code so we can fuzz it.
#git apply $SRC/crypto_patch.txt

echo "" >> ${BASE}/openvpn.c
echo "#include \"fake_fuzz_header.h\"" >> ${BASE}/openvpn.c
echo "ssize_t fuzz_get_random_data(void *buf, size_t len) { return 0; }" >> ${BASE}/fake_fuzz_header.h
echo "int fuzz_success;" >> ${BASE}/fake_fuzz_header.h

# Apply hooking changes
apply_sed_changes

# Copy corpuses out
zip -r $OUT/fuzz_verify_cert_seed_corpus.zip $SRC/boringssl/fuzz/cert_corpus

# Build fuzz_options seed corpus: sample configs + one file per option keyword
# plus a handful of richly-featured generated configs that exercise long add_option()
# dispatch chains the parser alone won't reach from random bytes.
OPT_SEEDS=$(mktemp -d)
cp $SRC/openvpn/sample/sample-config-files/client.conf $OPT_SEEDS/client.conf
cp $SRC/openvpn/sample/sample-config-files/server.conf $OPT_SEEDS/server.conf
cp $SRC/openvpn/sample/sample-config-files/loopback-client $OPT_SEEDS/loopback-client.conf
cp $SRC/openvpn/sample/sample-config-files/loopback-server $OPT_SEEDS/loopback-server.conf
grep -ohE 'streq\(p\[0\], "[^"]+"\)' $SRC/openvpn/src/openvpn/options.c \
    | sed -E 's/streq\(p\[0\], "([^"]+)"\)/\1/' | sort -u \
    | while read kw; do
        printf '%s\n' "$kw" > "$OPT_SEEDS/kw_${kw//\//_}"
    done

cat > $OPT_SEEDS/full-server <<'CFG'
mode server
tls-server
proto tcp-server
dev tun
local 0.0.0.0
port 1194
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
client-to-client
duplicate-cn
max-clients 100
client-config-dir ccd
ccd-exclusive
explicit-exit-notify 1
sndbuf 0
rcvbuf 0
mssfix 1450
tun-mtu 1500
fragment 1300
comp-lzo no
topology subnet
crl-verify crl.pem
remote-cert-tls client
tls-version-min 1.2
auth-user-pass-verify /etc/openvpn/check-creds.sh via-env
client-cert-not-required
username-as-common-name
script-security 2
auth-gen-token 3600
auth-gen-token-secret tokensec
route 10.0.0.0 255.0.0.0
route-ipv6 fc00::/7
push "route 192.168.10.0 255.255.255.0"
push "route-ipv6 2001:db8:1::/64"
push "dhcp-option DOMAIN example.com"
push "dhcp-option WINS 10.0.0.1"
inactive 3600
ping-timer-rem
reneg-sec 3600
CFG

cat > $OPT_SEEDS/full-client <<'CFG'
client
dev tun
proto udp4
remote vpn.example.com 1194
remote backup.example.com 443 tcp
remote-random
nobind
resolv-retry infinite
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
auth SHA256
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tls-version-min 1.2
remote-cert-tls server
verify-x509-name server-hostname name
auth-user-pass userpass.txt
tun-mtu 1500
mssfix 1450
fragment 0
http-proxy 192.0.2.1 3128 user.txt basic
http-proxy-option AGENT "Mozilla/5.0"
http-proxy-option CUSTOM-HEADER "X-Foo: bar"
socks-proxy 192.0.2.2 1080
keepalive 10 60
explicit-exit-notify 2
pull
pull-filter accept route
pull-filter ignore dhcp-option
pull-filter reject "redirect-gateway"
verb 4
mute 10
status status.log 60
log-append openvpn.log
auth-nocache
remote-random-hostname
data-ciphers-fallback AES-128-CBC
allow-compression no
CFG

cat > $OPT_SEEDS/static-key-config <<'CFG'
dev tap
ifconfig 10.0.0.1 255.255.255.0
secret static.key
cipher AES-256-CBC
auth SHA512
ping 10
ping-restart 60
mtu-test
shaper 2000
mark 42
bind ipv6only
allow-deprecated-insecure-static-crypto
CFG

cat > $OPT_SEEDS/with-inline-files <<'CFG'
client
dev tun
remote vpn.example.com
<ca>
-----BEGIN CERTIFICATE-----
MIIBuzCCAWQCCQDahGQ1RJUw
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBuzCCAWQCCQDahGQ1RJUw
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN RSA PRIVATE KEY-----
MIIBuzCCAWQCCQDahGQ1RJUw
-----END RSA PRIVATE KEY-----
</key>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abc
-----END OpenVPN Static key V1-----
</tls-auth>
auth SHA256
cipher AES-256-GCM
CFG

cat > $OPT_SEEDS/connections-multi <<'CFG'
client
dev tun
<connection>
remote a.example 1194 udp
remote-cert-tls server
</connection>
<connection>
remote b.example 443 tcp
http-proxy proxy.example 8080
</connection>
<connection>
remote c.example 1194 udp4
</connection>
ca ca.crt
cert c.crt
key c.key
CFG

cat > $OPT_SEEDS/dco-options <<'CFG'
client
dev tun
remote vpn.example.com
disable-dco
dco-allow-asym
data-ciphers AES-256-GCM
cipher AES-256-GCM
auth SHA256
CFG

cat > $OPT_SEEDS/route-heavy <<'CFG'
client
dev tun
remote vpn.example.com
route 192.168.0.0 255.255.0.0 vpn_gateway
route-ipv6 2001:db8::/32
route-gateway 10.8.0.1
route-metric 100
route-delay 5
redirect-gateway def1 bypass-dhcp ipv6 !ipv4
redirect-private autolocal block-local
route-nopull
dhcp-option DOMAIN example.com
dhcp-option DOMAIN-SEARCH alt.example
dhcp-option DNS 8.8.8.8
dhcp-option DNS6 2001:4860:4860::8888
dhcp-option WINS 192.168.1.1
dhcp-option NBT 8
dhcp-option NBDD 192.168.1.2
dhcp-option NBS 192.168.1.0
block-outside-dns
ip-win32 dynamic 0 86400
register-dns
CFG

cat > $OPT_SEEDS/push-heavy <<'CFG'
mode server
tls-server
proto udp
dev tun
ca ca.crt
cert s.crt
key s.key
dh dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1"
push "route 192.168.10.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option WINS 192.168.0.1"
push "dhcp-option DOMAIN example.com"
push "inactive 3600"
push "ping 10"
push "ping-restart 60"
push "ifconfig 10.8.0.2 10.8.0.1"
push "ifconfig-ipv6 2001:db8::2/64 2001:db8::1"
push "keepalive 10 60"
push "topology subnet"
push "comp-lzo no"
push-reset
push-remove route
push-remove dhcp-option
push-peer-info
CFG

(cd $OPT_SEEDS && zip -qr $OUT/fuzz_options_seed_corpus.zip .)

# Disable libFuzzer's leak detection: fatal-error code paths longjmp out of
# x_msg_va before its local gc_arena can be freed, which surfaces as a
# spurious leak only inside the harness, not in production OpenVPN.
cat > $OUT/fuzz_options.options <<'EOF'
[libfuzzer]
detect_leaks = 0
EOF

grep -ohE 'streq\(p\[0\], "[^"]+"\)' $SRC/openvpn/src/openvpn/options.c \
    | sed -E 's/streq\(p\[0\], "([^"]+)"\)/"\1"/' | sort -u > $OUT/fuzz_options.dict
rm -rf $OPT_SEEDS

# Build openvpn
autoreconf -ivf
./configure --disable-lz4 --with-crypto-library=openssl OPENSSL_LIBS="-L/usr/local/ssl/ -lssl -lcrypto" OPENSSL_CFLAGS="-I/usr/local/ssl/include/"
make -j$(nproc)

# Make openvpn object files into a library we can link fuzzers to
cd src/openvpn
rm openvpn.o
ar r libopenvpn.a *.o

# Compile our fuzz helper
$CXX $CXXFLAGS -g -c $SRC/fuzz_randomizer.cpp -o $SRC/fuzz_randomizer.o

# Compile the fuzzers
for fuzzname in dhcp misc base64 proxy buffer route packet_id mroute list verify_cert options; do
    $CC -DHAVE_CONFIG_H -I. -I../.. -I../../include -I../../src/compat -I/usr/include/libnl3/ \
      -DPLUGIN_LIBDIR=\"/usr/local/lib/openvpn/plugins\" -std=c99 $CFLAGS \
      -c $SRC/fuzz_${fuzzname}.c -o $SRC/fuzz_${fuzzname}.o

    # Link with CXX
    $CXX ${CXXFLAGS} ${LIB_FUZZING_ENGINE} $SRC/fuzz_${fuzzname}.o -o $OUT/fuzz_${fuzzname} $SRC/fuzz_randomizer.o \
        libopenvpn.a ../../src/compat/.libs/libcompat.a /usr/lib/x86_64-linux-gnu/libnsl.a \
        /usr/lib/x86_64-linux-gnu/libresolv.a /usr/lib/x86_64-linux-gnu/liblzo2.a \
        -lssl -lcrypto -ldl -l:libnl-3.a -l:libnl-genl-3.a -lcap-ng
done

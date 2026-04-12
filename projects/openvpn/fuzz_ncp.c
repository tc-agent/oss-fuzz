/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "config.h"
#include "syshead.h"
#include "ssl_ncp.h"
#include "buffer.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "fuzz_randomizer.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    OPENSSL_malloc_init();
    SSL_library_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_random_init(data, size);
    struct gc_arena gc = gc_new();

    char *peer_info = get_random_string();
    char *cipher_list = get_random_string();
    char *remote_cipher = get_random_string();

    tls_peer_supports_ncp(peer_info);
    tls_peer_ncp_list(peer_info, &gc);
    mutate_ncp_cipher_list(cipher_list, &gc);
    ncp_get_best_cipher(cipher_list, peer_info, remote_cipher, &gc);

    free(peer_info);
    free(cipher_list);
    free(remote_cipher);
    gc_free(&gc);
    fuzz_random_destroy();
    return 0;
}

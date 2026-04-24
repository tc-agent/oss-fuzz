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

/*
 * Fuzz harness for haproxy_srvr_parse_sa: parses HAProxy v1 and v2
 * protocol headers from fuzz-controlled input.
 */

#include <sys_defs.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <msg.h>
#include <myaddrinfo.h>
#include <haproxy_srvr.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MAI_HOSTADDR_STR smtp_client_addr;
    MAI_HOSTADDR_STR smtp_server_addr;
    MAI_SERVPORT_STR smtp_client_port;
    MAI_SERVPORT_STR smtp_server_port;
    struct sockaddr_storage client_sa;
    struct sockaddr_storage server_sa;
    SOCKADDR_SIZE client_sa_len;
    SOCKADDR_SIZE server_sa_len;
    int non_proxy;
    ssize_t str_len;
    char   *buf;

    buf = malloc(size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    memset(&client_sa, 0, sizeof(client_sa));
    memset(&server_sa, 0, sizeof(server_sa));
    client_sa_len = sizeof(client_sa);
    server_sa_len = sizeof(server_sa);
    non_proxy = 0;
    str_len = (ssize_t)size;

    haproxy_srvr_parse_sa(buf, &str_len, &non_proxy,
                          &smtp_client_addr, &smtp_client_port,
                          &smtp_server_addr, &smtp_server_port,
                          (struct sockaddr *) &client_sa, &client_sa_len,
                          (struct sockaddr *) &server_sa, &server_sa_len);
    free(buf);
    return 0;
}

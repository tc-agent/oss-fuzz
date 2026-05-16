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

#include <sys_defs.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <myaddrinfo.h>
#include "haproxy_srvr.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 8192)
        return 0;
    char *buf = (char *) malloc(size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    ssize_t str_len = (ssize_t) size;
    int non_proxy = 0;
    MAI_HOSTADDR_STR client_addr, server_addr;
    MAI_SERVPORT_STR client_port, server_port;
    (void) haproxy_srvr_parse(buf, &str_len, &non_proxy,
                              &client_addr, &client_port,
                              &server_addr, &server_port);

    free(buf);
    return 0;
}

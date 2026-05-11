/* Copyright 2021 Google LLC
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

#include "fuzz_header.h"

/*
 * Targets dhcp_reply directly. dhcp_packet() does a blocking recvmsg()
 * on a real socket which is unusable inside libFuzzer.
 */
void FuzzDhcp(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  if (size < sizeof(struct dhcp_packet) + 8)
    return;

  size_t buf_sz = sizeof(struct dhcp_packet) * 2;
  char *buf = (char *)malloc(buf_sz);
  if (!buf) return;
  memset(buf, 0, buf_sz);

  size_t copy_sz = size > sizeof(struct dhcp_packet) ? sizeof(struct dhcp_packet) : size;
  memcpy(buf, data, copy_sz);

  daemon->dhcp_packet.iov_base = buf;
  daemon->dhcp_packet.iov_len = buf_sz;

  int int_index = 0;
  time_t now = 0;
  int unicast_dest = 0, loopback = 0, is_inform = 0;
  struct in_addr fallback;
  struct in_addr leasequery_source;
  memset(&fallback, 0, sizeof(fallback));
  memset(&leasequery_source, 0, sizeof(leasequery_source));

  dhcp_reply(daemon->dhcp, (char *)"lo", int_index, copy_sz, now,
             unicast_dest, loopback, &is_inform, 0, fallback, now,
             leasequery_source);

  free(daemon->dhcp_packet.iov_base);
  daemon->dhcp_packet.iov_base = NULL;
}

/*
 * Fuzzer entrypoint.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 1) {
    return 0;
  }

  gb_init();

  data += 1;
  size -= 1;

  int succ = init_daemon(&data, &size);

  if (succ == 0) {
    cache_init();
    blockdata_init();

    FuzzDhcp(&data, &size);

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  gb_cleanup();
  return 0;
}

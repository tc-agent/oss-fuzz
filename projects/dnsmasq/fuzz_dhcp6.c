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
 * Targets dhcp6_reply directly. dhcp6_packet() does a blocking recvmsg()
 * on a real socket which is unusable inside libFuzzer.
 */
void FuzzDhcp6(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  if (size < 32)
    return;

  size_t buf_sz = 1024;
  char *buf = (char *)malloc(buf_sz);
  if (!buf) return;
  memset(buf, 0, buf_sz);

  size_t copy_sz = size > buf_sz ? buf_sz : size;
  memcpy(buf, data, copy_sz);

  daemon->dhcp_packet.iov_base = buf;
  daemon->dhcp_packet.iov_len = buf_sz;
  daemon->outpacket.iov_base = NULL;
  daemon->outpacket.iov_len = 0;

  /* multicast_dest must be set for non-RELAY-FORW messages, otherwise
     dhcp6_reply bails out immediately. */
  int multicast_dest = 1, interface = 0;
  struct in6_addr fallback, ll_addr, ula_addr, client_addr;
  memset(&fallback, 0, sizeof(fallback));
  memset(&ll_addr, 0, sizeof(ll_addr));
  memset(&ula_addr, 0, sizeof(ula_addr));
  memset(&client_addr, 0, sizeof(client_addr));

  time_t now = 0;
  dhcp6_reply(daemon->dhcp6, multicast_dest, interface, (char *)"lo",
              &fallback, &ll_addr, &ula_addr, copy_sz,
              &client_addr, now);

  free(daemon->dhcp_packet.iov_base);
  daemon->dhcp_packet.iov_base = NULL;
  if (daemon->outpacket.iov_base) {
    free(daemon->outpacket.iov_base);
    daemon->outpacket.iov_base = NULL;
  }
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

    FuzzDhcp6(&data, &size);

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  gb_cleanup();
  return 0;
}

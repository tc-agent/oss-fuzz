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
 * Targets dhcp6_reply (rfc3315.c) directly, bypassing the socket layer.
 * dhcp6_packet() calls recvmsg() to read the packet — without a real socket
 * that always fails immediately. Calling dhcp6_reply() directly with crafted
 * data exercises the full DHCPv6 message parsing logic.
 */
void FuzzDhcp6(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;
  time_t now = 0;

  if (size < 4)
    return;

  void *packet_buf = malloc(size);
  if (!packet_buf) return;
  memcpy(packet_buf, data, size);

  daemon->dhcp_packet.iov_base = packet_buf;
  daemon->dhcp_packet.iov_len = size;

  char iface_name[IF_NAMESIZE] = "eth0";
  struct in6_addr fallback, ll_addr, ula_addr, client_addr;
  memset(&fallback, 0, sizeof(fallback));
  memset(&ll_addr, 0, sizeof(ll_addr));
  memset(&ula_addr, 0, sizeof(ula_addr));
  memset(&client_addr, 0, sizeof(client_addr));

  /* multicast_dest=1 so non-relay messages are processed (RFC-9915 §16) */
  dhcp6_reply(daemon->dhcp6, 1, 1, iface_name,
              &fallback, &ll_addr, &ula_addr,
              size, &client_addr, now);

  free(daemon->dhcp_packet.iov_base);
  daemon->dhcp_packet.iov_base = NULL;
  /* dhcp6_reply writes to daemon->outpacket (separate from dhcp_packet) */
  free(daemon->outpacket.iov_base);
  daemon->outpacket.iov_base = NULL;
}

/*
 * Fuzzer entrypoint.
 */ 
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 1) {
    return 0;
  }

  // Initialize mini garbage collector
  gb_init();

  // Get a value we can use to decide which target to hit.
  int i = (int)data[0];
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

  // Free data in mini garbage collector.
  gb_cleanup();

  return 0;
}

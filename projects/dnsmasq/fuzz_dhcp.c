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
 * Targets dhcp_reply (rfc2131.c) directly, bypassing the socket layer.
 * dhcp_packet() calls recv_dhcp_packet() which calls recvmsg() — without a
 * real socket that always fails immediately. Calling dhcp_reply() directly
 * with crafted data exercises the full DHCP option parsing and reply logic.
 */
void FuzzDhcp(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;
  time_t now = 0;

  if (size < sizeof(struct dhcp_packet))
    return;

  void *packet_buf = malloc(size);
  if (!packet_buf) return;
  memcpy(packet_buf, data, size);

  daemon->dhcp_packet.iov_base = packet_buf;
  daemon->dhcp_packet.iov_len = size;

  char iface_name[IF_NAMESIZE] = "eth0";
  int is_inform = 0;
  struct in_addr fallback;
  fallback.s_addr = 0;

  dhcp_reply(daemon->dhcp, iface_name, 1, size, now, 0, 0,
             &is_inform, 0, fallback, now, fallback);

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

		FuzzDhcp(&data, &size);

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  // Free data in mini garbage collector.
  gb_cleanup();
  return 0;
}

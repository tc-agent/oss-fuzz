// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Fuzzes ip_packet_create() in libipsec.
 *
 * Exercises IPv4/IPv6 header parsing, extension header traversal, and TCP/UDP
 * sub-header extraction in ip_packet.c.  No plugins are needed since
 * ip_packet_create() is pure struct parsing.
 */

#include <library.h>
#include <utils/debug.h>
#include <ip_packet.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_ip_packet");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	ip_packet_t *packet;

	/* ip_packet_create takes ownership of (and may free) the chunk, so clone */
	packet = ip_packet_create(chunk_clone(chunk_create((u_char *)buf, len)));
	DESTROY_IF(packet);
	return 0;
}

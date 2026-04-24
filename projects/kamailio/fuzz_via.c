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
//
////////////////////////////////////////////////////////////////////////////////
/*
 * fuzz_via.c - libFuzzer harness for Kamailio Via header parser
 *
 * The Via header is present in every SIP request and response and is a
 * primary target for malformed-input attacks. This harness exercises
 * parse_via() directly, bypassing the full SIP message parser so that
 * the fuzzer can focus on Via-specific parsing logic including parameters
 * (branch, rport, received, maddr, ttl), comma-separated Via lists, and
 * edge cases around whitespace and quoted strings.
 */

#include "../config.h"
#include "../parser/parse_via.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if(size < 2 || size > 4096) {
		return 0;
	}

	/* Make a mutable copy since the parser may modify the input. */
	char *buf = (char *)malloc(size + 1);
	if(buf == NULL) {
		return 0;
	}
	memcpy(buf, data, size);
	buf[size] = '\0';

	/* free_via_list() frees the passed node itself (not just nested data),
	 * so we must heap-allocate vb rather than use a stack variable. */
	struct via_body *vb = (struct via_body *)malloc(sizeof(struct via_body));
	if(vb == NULL) {
		free(buf);
		return 0;
	}
	memset(vb, 0, sizeof(struct via_body));

	parse_via(buf, buf + size, vb);
	free_via_list(vb); /* frees vb and any dynamically-allocated next/params */

	free(buf);
	return 0;
}

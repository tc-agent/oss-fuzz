/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "confile_utils.h"
#include "lxctest.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char type;
	unsigned long nsid, hostid, range;
	char *input;

	if (size > 4096)
		return 0;

	input = (char *)malloc(size + 1);
	lxc_test_assert_abort(input);
	memcpy(input, data, size);
	input[size] = '\0';

	/*
	 * Exercise parse_idmaps() directly. This function implements a
	 * hand-rolled whitespace-splitting state machine over strings of the
	 * form "u <nsid> <hostid> <range>" and is not reached by the generic
	 * config-read harness unless the fuzzer happens to emit a correctly
	 * prefixed config key.
	 */
	(void) parse_idmaps(input, &type, &nsid, &hostid, &range);

	free(input);
	return 0;
}

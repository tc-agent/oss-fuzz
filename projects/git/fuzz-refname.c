/*
 * Copyright 2026 Google Inc.
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

#include "git-compat-util.h"
#include "refs.h"
#include "strbuf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct strbuf buf = STRBUF_INIT;

	strbuf_add(&buf, data, size);

	check_refname_format(buf.buf, 0);
	check_refname_format(buf.buf, REFNAME_ALLOW_ONELEVEL);
	check_refname_format(buf.buf, REFNAME_REFSPEC_PATTERN);

	strbuf_release(&buf);
	return 0;
}

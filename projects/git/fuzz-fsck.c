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

#define USE_THE_REPOSITORY_VARIABLE

#include "git-compat-util.h"
#include "fsck.h"
#include "repository.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fsck_options options;
	struct object_id oid = { 0 };
	enum object_type type;

	if (size < 1)
		return 0;

	switch (data[0] % 4) {
	case 0: type = OBJ_COMMIT; break;
	case 1: type = OBJ_TREE;   break;
	case 2: type = OBJ_BLOB;   break;
	default: type = OBJ_TAG;   break;
	}
	data += 1;
	size -= 1;

	memset(the_repository, 0, sizeof(*the_repository));
	initialize_repository(the_repository);
	repo_set_hash_algo(the_repository, GIT_HASH_SHA1);

	fsck_options_init(&options, the_repository, FSCK_OPTIONS_DEFAULT);
	fsck_buffer(&oid, type, data, size, &options);
	fsck_options_clear(&options);

	repo_clear(the_repository);
	return 0;
}

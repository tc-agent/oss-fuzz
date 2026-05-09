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
#include "commit.h"
#include "repository.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct commit *commit;
	struct object_id oid = { 0 };

	memset(the_repository, 0, sizeof(*the_repository));
	initialize_repository(the_repository);
	repo_set_hash_algo(the_repository, GIT_HASH_SHA1);

	commit = lookup_commit(the_repository, &oid);
	if (commit)
		parse_commit_buffer(the_repository, commit, data, size, 0);

	repo_clear(the_repository);
	return 0;
}

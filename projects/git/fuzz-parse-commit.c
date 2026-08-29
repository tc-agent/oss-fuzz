#define USE_THE_REPOSITORY_VARIABLE

#include "git-compat-util.h"
#include "commit.h"
#include "repository.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct commit *c;
	struct object_id oid = {{ 0 }};

	memset(the_repository, 0, sizeof(*the_repository));
	initialize_repository(the_repository);
	repo_set_hash_algo(the_repository, GIT_HASH_SHA1);

	c = lookup_commit(the_repository, &oid);
	if (c) {
		/*
		 * Clear parsed flag so parse_commit_buffer() actually
		 * processes the data.
		 */
		c->object.parsed = 0;
		parse_commit_buffer(the_repository, c, (const void *)data,
				    size, 0);
	}

	repo_clear(the_repository);

	return 0;
}

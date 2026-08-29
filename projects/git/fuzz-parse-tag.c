#define USE_THE_REPOSITORY_VARIABLE

#include "git-compat-util.h"
#include "tag.h"
#include "repository.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct tag *t;
	struct object_id oid = {{ 0 }};

	memset(the_repository, 0, sizeof(*the_repository));
	initialize_repository(the_repository);
	repo_set_hash_algo(the_repository, GIT_HASH_SHA1);

	t = lookup_tag(the_repository, &oid);
	if (t) {
		t->object.parsed = 0;
		parse_tag_buffer(the_repository, t, (const void *)data, size);
	}

	repo_clear(the_repository);

	return 0;
}

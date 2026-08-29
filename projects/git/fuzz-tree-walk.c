#define USE_THE_REPOSITORY_VARIABLE

#include "git-compat-util.h"
#include "tree-walk.h"
#include "repository.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct tree_desc desc;
	struct name_entry entry;
	struct object_id fake_oid = {{ 0 }};

	memset(the_repository, 0, sizeof(*the_repository));
	initialize_repository(the_repository);
	repo_set_hash_algo(the_repository, GIT_HASH_SHA1);

	if (init_tree_desc_gently(&desc, &fake_oid, data, size, 0))
		goto cleanup;

	while (tree_entry_gently(&desc, &entry))
		; /* walk all entries */

cleanup:
	repo_clear(the_repository);

	return 0;
}

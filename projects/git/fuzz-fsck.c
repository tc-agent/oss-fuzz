#define USE_THE_REPOSITORY_VARIABLE

#include "git-compat-util.h"
#include "fsck.h"
#include "repository.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fsck_options options;
	struct object_id oid = {{ 0 }};
	enum object_type types[] = {OBJ_COMMIT, OBJ_TREE, OBJ_TAG, OBJ_BLOB};
	enum object_type type;

	if (size < 1)
		return 0;

	memset(the_repository, 0, sizeof(*the_repository));
	initialize_repository(the_repository);
	repo_set_hash_algo(the_repository, GIT_HASH_SHA1);

	fsck_options_init(&options, the_repository, FSCK_OPTIONS_DEFAULT);
	options.error_func = fsck_objects_error_function;

	/*
	 * Use the first byte to select the object type to validate,
	 * then pass the rest as object data.
	 */
	type = types[data[0] % ARRAY_SIZE(types)];
	fsck_buffer(&oid, type, data + 1, size - 1, &options);

	fsck_options_clear(&options);
	repo_clear(the_repository);

	return 0;
}

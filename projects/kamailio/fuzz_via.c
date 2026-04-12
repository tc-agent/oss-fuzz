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

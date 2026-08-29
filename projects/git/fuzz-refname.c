#include "git-compat-util.h"
#include "refs.h"
#include "strbuf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct strbuf buf = STRBUF_INIT;

	strbuf_add(&buf, data, size);

	/*
	 * Exercise check_refname_format with various flag
	 * combinations to cover more validation paths.
	 */
	check_refname_format(buf.buf, 0);
	check_refname_format(buf.buf, REFNAME_ALLOW_ONELEVEL);
	check_refname_format(buf.buf,
			     REFNAME_ALLOW_ONELEVEL | REFNAME_REFSPEC_PATTERN);

	strbuf_release(&buf);
	return 0;
}

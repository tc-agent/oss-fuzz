/*
 * Copyright (c) 2026 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Fuzz the tmux key-string parser (key_string_lookup_string).
 *
 * This exercises:
 *   - key-string.c (key_string_lookup_string, key_string_get_modifiers,
 *                   key_string_search_table, key_string_lookup_key)
 *   - utf8.c (UTF-8 multi-byte key parsing)
 *
 * key_string_lookup_string handles: modifier prefixes (C-, M-, S-), special
 * key names (F1, Up, Home), hex codes (0x41), UTF-8 sequences, and the large
 * mouse key table. key_string_lookup_key does the reverse (key code to string).
 */

#include <stddef.h>
#include <string.h>

#include "tmux.h"

struct event_base *libevent;

int
LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
	char		*buf;
	key_code	 key;

	if (size > 128 || size == 0)
		return 0;

	buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	/* Parse the key string. */
	key = key_string_lookup_string(buf);

	/*
	 * Round-trip: convert back to string. This exercises key_string_lookup_key
	 * including the key code → string table lookups, Unicode handling, and
	 * flag formatting.
	 */
	if (key != KEYC_UNKNOWN) {
		key_string_lookup_key(key, 0);
		key_string_lookup_key(key, 1);
	}

	free(buf);
	return 0;
}

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
	const struct options_table_entry	*oe;

	global_environ = environ_create();
	global_options = options_create(NULL);
	global_s_options = options_create(NULL);
	global_w_options = options_create(NULL);
	for (oe = options_table; oe->name != NULL; oe++) {
		if (oe->scope & OPTIONS_TABLE_SERVER)
			options_default(global_options, oe);
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(global_s_options, oe);
		if (oe->scope & OPTIONS_TABLE_WINDOW)
			options_default(global_w_options, oe);
	}
	libevent = osdep_event_init();
	socket_path = xstrdup("dummy");

	return 0;
}

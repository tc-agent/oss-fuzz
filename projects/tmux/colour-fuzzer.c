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
 * Fuzz the tmux colour parsing routines.
 *
 * This exercises:
 *   - colour.c (colour_fromstring, colour_byname, colour_parseX11,
 *               colour_tostring, colour_totheme, colour_force_rgb,
 *               colour_256toRGB, colour_256to16, colour_find_rgb)
 *
 * colour_fromstring handles: named colours ("red"), indexed ("colour123"),
 * RGB hex ("#rrggbb"), and falls through to colour_byname for X11 names.
 * colour_parseX11 handles: "rgb:rr/gg/bb", "#rrggbb", "r,g,b",
 * "cmyk:c/m/y/k", and named X11 colour names.
 *
 * The X11 name table in colour_byname is ~600 entries and is only reachable
 * via these two entry points; no existing fuzzer targets them directly.
 */

#include <stddef.h>
#include <string.h>

#include "tmux.h"

struct event_base *libevent;

int
LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
	char	*buf;
	int	 c;
	u_char	 r, g, b;

	if (size > 512 || size == 0)
		return 0;

	buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	/* Exercise colour_fromstring -> colour_byname path. */
	c = colour_fromstring(buf);
	if (c != -1) {
		colour_tostring(c);
		colour_totheme(c);
		colour_force_rgb(c);
		colour_split_rgb(c, &r, &g, &b);
		colour_find_rgb(r, g, b);
		colour_256to16(c);
	}

	/* Exercise colour_parseX11 directly (rgb:, cmyk:, X11 names). */
	colour_parseX11(buf);

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

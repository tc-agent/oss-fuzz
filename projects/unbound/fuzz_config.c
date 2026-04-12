/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for unbound's configuration file parser.
 * Exercises util/config_file.c, util/configlexer.c, util/configparser.c.
 */

#include "config.h"
#include "util/config_file.h"
#include "util/log.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char fname[] = "/tmp/fuzz_unbound_cfg_XXXXXX";
	int fd;
	size_t pos = 0;
	struct config_file *cfg;

	fd = mkstemp(fname);
	if (fd == -1)
		return 0;
	while (pos < size) {
		ssize_t n = write(fd, data + pos, size - pos);
		if (n <= 0) {
			if (n == -1 && errno == EINTR)
				continue;
			break;
		}
		pos += (size_t)n;
	}
	close(fd);

	log_init(NULL, 0, NULL);
	cfg = config_create();
	if (cfg) {
		config_read(cfg, fname, NULL);
		config_delete(cfg);
	}
	unlink(fname);
	return 0;
}

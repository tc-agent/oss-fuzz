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
 * Fuzzer for unbound's zone file parser (authzone.c).
 * Exercises auth_zones_apply_cfg -> auth_zone_read_zonefile -> az_parse_file
 * and the full zone record parsing path.
 */

#include "config.h"
#include "services/authzone.h"
#include "util/config_file.h"
#include "util/log.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char fname[] = "/tmp/fuzz_unbound_zone_XXXXXX";
	int fd;
	size_t pos = 0;
	struct auth_zones *az = NULL;
	struct config_file *cfg = NULL;
	struct config_auth auth;
	int is_rpz = 0;

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
	if (!cfg)
		goto out;

	/* Minimal auth zone config entry pointing at our temp file. */
	memset(&auth, 0, sizeof(auth));
	auth.name = (char *)"example.com.";
	auth.zonefile = fname;
	auth.for_downstream = 1;
	auth.for_upstream = 0;
	cfg->auths = &auth;

	az = auth_zones_create();
	if (!az)
		goto out;

	/* NULL env/mods: skips ZONEMD verification, just parses the file */
	auth_zones_apply_cfg(az, cfg, 0, &is_rpz, NULL, NULL);

out:
	/* Unlink auth from cfg before config_delete to avoid double-free */
	if (cfg) {
		cfg->auths = NULL;
		config_delete(cfg);
	}
	if (az)
		auth_zones_delete(az);
	unlink(fname);
	return 0;
}

/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "conf.h"
#include "confile.h"
#include "lxctest.h"
#include "utils.h"

/*
 * Prepend a minimal veth network device declaration so that subsequent
 * lxc.net.0.* lines (from the fuzzer) are routed into the per-netdev
 * setters (IP address, gateway, route, VLAN, MTU, …) rather than being
 * silently dropped because no netdev was ever allocated.
 */
static const char net_header[] = "lxc.net.0.type = veth\n";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int fd = -1;
	char tmpf[] = "/tmp/fuzz-lxc-config-net-XXXXXX";
	struct lxc_conf *conf = NULL;

	if (size > 102400)
		return 0;

	fd = lxc_make_tmpfile(tmpf, false);
	lxc_test_assert_abort(fd >= 0);

	/* Seed the config file with a veth netdev so net-specific keys work. */
	lxc_write_nointr(fd, net_header, sizeof(net_header) - 1);
	/* Append the fuzzer-controlled config lines. */
	lxc_write_nointr(fd, data, size);
	close(fd);

	conf = lxc_conf_init();
	lxc_test_assert_abort(conf);
	lxc_config_read(tmpf, conf, false);
	lxc_conf_free(conf);

	(void) unlink(tmpf);
	return 0;
}

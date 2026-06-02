// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "conf.h"
#include "parser.h"
#include "configdb.h"
#include "dirtree.h"
#include "stash.h"
#include "modules.h"
#include "netaddr.h"
#include "regexp.h"
#include "json.h"
#include "var.h"
#include "class.h"
#include "fsio.h"

extern int modules_init(void);
extern void init_inet(void);
extern void init_netio(void);

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pool *p;
  char path[64];
  int fd;
  xaset_t *parsed_servers = NULL;

  if (size < 1 || size > 16384) {
    return 0;
  }

  if (!initialized) {
    init_pools();
    init_regexp();
    init_inet();
    init_netio();
    init_netaddr();
    init_fs();
    init_class();
    init_config();
    init_dirtree();
    init_stash();
    init_json();
    (void) var_init();
    /* Register the static modules so config directives dispatch into their
     * conftab handlers; this is what brings module code under fuzzing. */
    (void) modules_init();
    initialized = 1;
  }

  /* Use /dev/shm so the parser's open/read calls hit tmpfs, not disk. */
  snprintf(path, sizeof(path), "/dev/shm/cfg-%d.conf", getpid());
  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return 0;
  (void) write(fd, data, size);
  close(fd);

  p = make_sub_pool(NULL);
  if (p == NULL) {
    unlink(path);
    return 0;
  }

  if (pr_parser_prepare(p, &parsed_servers) == 0) {
    /* PR_PARSER_FL_DYNAMIC_CONFIG is the flag proftpd uses for .ftpaccess
     * files, which are the operator-allowed, attacker-influenced parsing
     * path: a user may drop a .ftpaccess into a writable directory and the
     * server parses it at runtime. Unknown directives become warnings rather
     * than fatal errors. */
    (void) pr_parser_parse_file(p, path, NULL, PR_PARSER_FL_DYNAMIC_CONFIG);
    (void) pr_parser_cleanup();
  }

  destroy_pool(p);
  unlink(path);
  return 0;
}

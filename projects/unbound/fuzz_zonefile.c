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
 * Fuzz the zone file parser via auth_zones_apply_cfg() (services/authzone.c).
 * Writes fuzz input to a temp file, sets it as the zonefile for example.com.,
 * and calls auth_zones_apply_cfg().
 *
 * The config_auth struct is stack-allocated with string literal pointers;
 * cfg->auths is set to NULL before config_delete() to prevent config_delauths()
 * from trying to free them.
 */
#include "config.h"
#include <string.h>
#include <unistd.h>
#include "util/config_file.h"
#include "util/log.h"
#include "services/authzone.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char fname[] = "/tmp/fuzz_zonefile_XXXXXX";
  int fd = mkstemp(fname);
  if (fd < 0)
    return 0;

  if (write(fd, data, size) != (ssize_t)size) {
    close(fd);
    unlink(fname);
    return 0;
  }
  close(fd);

  log_init("/tmp/foo", 0, NULL);

  struct config_file *cfg = config_create();
  if (!cfg) {
    unlink(fname);
    return 0;
  }

  struct auth_zones *az = auth_zones_create();
  if (!az) {
    config_delete(cfg);
    unlink(fname);
    return 0;
  }

  struct config_auth auth;
  memset(&auth, 0, sizeof(auth));
  auth.name = "example.com.";
  auth.zonefile = fname;
  auth.for_downstream = 1;
  auth.for_upstream = 1;
  auth.next = NULL;

  cfg->auths = &auth;

  int is_rpz = 0;
  (void)auth_zones_apply_cfg(az, cfg, 0, &is_rpz, NULL, NULL);

  /* Prevent config_delete from freeing our stack-allocated config_auth. */
  cfg->auths = NULL;

  auth_zones_delete(az);
  config_delete(cfg);
  unlink(fname);
  return 0;
}

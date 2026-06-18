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
 * Fuzz the unbound configuration file parser (util/config_file.c).
 * Writes fuzz input to a temp file and calls config_read().
 *
 * Note: the flex/bison tokenizer leaks a small number of tokens on every
 * parse; disable LSAN via fuzz_config_fuzzer.options to avoid spurious exits.
 */
#include "config.h"
#include <unistd.h>
#include "util/config_file.h"
#include "util/log.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char fname[] = "/tmp/fuzz_config_XXXXXX";
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
  if (cfg) {
    (void)config_read(cfg, fname, NULL);
    config_delete(cfg);
  }

  unlink(fname);
  return 0;
}

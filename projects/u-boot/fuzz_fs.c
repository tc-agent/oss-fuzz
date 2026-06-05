/* Copyright 2026 Google LLC
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
 *
 * Generic filesystem fuzz harness. Uses u-boot's `ls` command which
 * auto-detects the filesystem type, so a single seed corpus covers FAT,
 * ext4, btrfs, SquashFS, and any other filesystem compiled in. Both
 * partitioned (`host 0:0`) and raw (`host 0`) binds are exercised so
 * partition-table-less images (e.g. SquashFS) are reachable.
 */

#include <command.h>
#include <os.h>
#include <test/fuzz.h>

/*
 * LeakSanitizer suppressions. u-boot's sandbox initialisation probes
 * cros_ec, which calloc's a key-scan matrix in keyscan_read_fdt_matrix()
 * and never frees it before exit. That isn't a bug in the parsers we're
 * fuzzing, but LSan flags it and aborts `-merge=1` runs (every new seed
 * then looks "redundant" since the binary aborts before any is processed).
 * `__lsan_default_suppressions` is honoured even when ASAN_OPTIONS is set
 * via the environment (which the base-runner image does).
 */
const char *__lsan_default_suppressions(void)
{
	return "leak:keyscan_read_fdt_matrix\n"
	       "leak:cros_ec_probe\n";
}

#define FUZZ_DISK_PATH "/tmp/fuzz_fs.img"

static int fuzz_fs(const uint8_t *data, size_t size)
{
	int fd;

	if (size < 512)
		return 0;

	fd = os_open(FUZZ_DISK_PATH, OS_O_WRONLY | OS_O_CREAT | OS_O_TRUNC);
	if (fd < 0)
		return 0;
	os_write(fd, data, size);
	os_close(fd);

	run_command("host bind 0 " FUZZ_DISK_PATH, 0);
	run_command("ls host 0:0 /", 0);
	run_command("ls host 0 /", 0);
	run_command("host unbind 0", 0);

	return 0;
}
FUZZ_TEST(fuzz_fs, 0);

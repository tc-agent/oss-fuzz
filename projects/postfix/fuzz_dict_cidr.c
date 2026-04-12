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
 * Fuzz harness for dict_cidr: parses a CIDR-based lookup table from
 * fuzz-controlled content and exercises open + lookup.
 */

#include <sys_defs.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <msg.h>
#include <vstring.h>
#include <dict.h>
#include <dict_cidr.h>

/* Fixed lookup keys covering IPv4, IPv6, and edge cases. */
static const char *const lookup_keys[] = {
    "127.0.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "::1",
    "2001:db8::1",
    "::ffff:192.0.2.1",
    "not-an-address",
};
#define NKEYS (sizeof(lookup_keys) / sizeof(lookup_keys[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char tmpfile[] = "/tmp/fuzz_dict_cidr_XXXXXX";
    int fd;
    DICT *dict;
    size_t i;

    fd = mkstemp(tmpfile);
    if (fd < 0)
        return 0;

    /* Write fuzz data as the CIDR map file content. */
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        return 0;
    }
    close(fd);

    dict = dict_cidr_open(tmpfile, O_RDONLY, DICT_FLAG_NONE);
    if (dict != NULL) {
        for (i = 0; i < NKEYS; i++)
            dict_get(dict, lookup_keys[i]);
        dict_close(dict);
    }

    unlink(tmpfile);
    return 0;
}

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

#include "fuzz_header.h"

/* one_opt is normally static in option.c; build.sh un-statics it. */
int one_opt(int option, char *arg, char *errstr, char *gen_err,
            int command_line, int servers_only);

/*
 * Drives one_opt() over a randomly-selected option code with a
 * fuzz-derived argument. one_opt is the meat of dnsmasq's config-line
 * parser (--server=..., --address=..., --dhcp-host=..., etc.).
 *
 * Each call may longjmp out via die(); we don't catch that, libfuzzer
 * does. Each call may allocate into daemon-> linked lists; daemon is
 * reset between iterations.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 8) return 0;

  gb_init();

  /* First 2 bytes pick an option code. The mapping below covers the
     short ASCII options ('a'..'z', 'A'..'Z') and the LOPT range
     [256, 391]. */
  uint16_t opt_pick = ((uint16_t)data[0] << 8) | data[1];
  data += 2;
  size -= 2;

  /* Pool of well-known option codes from option.c (sampled rather
     than enumerated to keep the harness simple). */
  /* Every option code one_opt() dispatches on: ASCII short options
     plus LOPT_ range 256..391 inclusive. */
  static const int opt_pool[] = {
    'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F', 'g',
    'G', 'h', 'H', 'i', 'I', 'J', 'k', 'K', 'l', 'L', 'm', 'M', 'n',
    'N', 'o', 'O', 'p', 'P', 'q', 'Q', 'r', 'R', 's', 'S', 't', 'T',
    'u', 'U', 'v', 'V', 'w', 'W', 'x', 'X', 'y', 'Y', 'z', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268,
    269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281,
    282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294,
    295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307,
    308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320,
    321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333,
    334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346,
    347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359,
    360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372,
    373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385,
    386, 387, 388, 389, 390, 391,
  };
  int option = opt_pool[opt_pick % (sizeof(opt_pool) / sizeof(opt_pool[0]))];

  /* Arg is the rest of the input as a NUL-terminated C string. Some
     one_opt branches mutate the arg, so use a private mutable copy. */
  char *arg = (char *)malloc(size + 1);
  if (!arg) return 0;
  memcpy(arg, data, size);
  arg[size] = '\0';

  /* one_opt writes its own errstr; provide a 512-byte scratch. */
  char errstr[512];
  errstr[0] = '\0';

  /* one_opt reads daemon-> for a few state checks; install a minimal
     daemon. We can't reuse fuzz_header's init_daemon as-is (it expects
     a much larger preamble); use a tiny stub instead. */
  daemon = (struct daemon *)gb_alloc_data(sizeof(struct daemon));
  if (!daemon) goto cleanup;
  daemon->namebuff = (char *)gb_alloc_data(MAXDNAME * 4);
  daemon->dhcp_buff = (char *)gb_alloc_data(DHCP_BUFF_SZ);
  daemon->dhcp_buff2 = (char *)gb_alloc_data(DHCP_BUFF_SZ);
  daemon->dhcp_buff3 = (char *)gb_alloc_data(DHCP_BUFF_SZ);
  daemon->addrbuff = (char *)gb_alloc_data(64);

  /* Arm the fuzz-aware die() so config errors longjmp back here. */
  fuzz_die_active = 1;
  if (setjmp(fuzz_die_jmp) == 0) {
    one_opt(option, arg, errstr, "error", /*command_line=*/0,
            /*servers_only=*/0);
  }
  fuzz_die_active = 0;

cleanup:
  free(arg);
  gb_cleanup();
  return 0;
}

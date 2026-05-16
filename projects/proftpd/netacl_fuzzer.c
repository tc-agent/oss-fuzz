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

#include "conf.h"
#include "netacl.h"
#include "netaddr.h"

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pool *p;
  char *acl_str;
  pr_netacl_t *acl;

  if (size == 0 || size > 4096) {
    return 0;
  }

  if (!initialized) {
    init_netaddr();
    initialized = 1;
  }

  acl_str = malloc(size + 1);
  if (acl_str == NULL) {
    return 0;
  }
  memcpy(acl_str, data, size);
  acl_str[size] = '\0';

  p = make_sub_pool(NULL);
  if (p == NULL) {
    free(acl_str);
    return 0;
  }

  acl = pr_netacl_create(p, acl_str);
  if (acl != NULL) {
    (void) pr_netacl_get_negated(acl);
    (void) pr_netacl_get_type(acl);
    (void) pr_netacl_get_str(p, acl);
    (void) pr_netacl_get_str2(p, acl, 0);
    (void) pr_netacl_dup(p, acl);
  }

  destroy_pool(p);
  free(acl_str);
  return 0;
}

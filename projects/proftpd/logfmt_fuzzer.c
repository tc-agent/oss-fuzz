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
#include "jot.h"
#include "logfmt.h"

static int parse_on_meta(pool *p, pr_jot_ctx_t *ctx, unsigned char id,
    const char *text, size_t text_len) {
  return 0;
}

static int parse_on_unknown(pool *p, pr_jot_ctx_t *ctx, const char *text,
    size_t text_len) {
  return 0;
}

static int parse_on_other(pool *p, pr_jot_ctx_t *ctx, char ch) {
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pool *p;
  char *text;
  pr_jot_ctx_t *jot_ctx;
  pr_jot_filters_t *filters;

  if (size == 0 || size > 4096) {
    return 0;
  }

  text = malloc(size + 1);
  if (text == NULL) {
    return 0;
  }
  memcpy(text, data, size);
  text[size] = '\0';

  p = make_sub_pool(NULL);
  if (p == NULL) {
    free(text);
    return 0;
  }

  jot_ctx = pcalloc(p, sizeof(pr_jot_ctx_t));
  (void) pr_jot_parse_logfmt(p, text, jot_ctx, parse_on_meta, parse_on_unknown,
    parse_on_other, 0);

  filters = pr_jot_filters_create(p, text, PR_JOT_FILTER_TYPE_CLASSES, 0);
  if (filters != NULL) {
    (void) pr_jot_filters_destroy(filters);
  }

  filters = pr_jot_filters_create(p, text, PR_JOT_FILTER_TYPE_COMMANDS, 0);
  if (filters != NULL) {
    (void) pr_jot_filters_destroy(filters);
  }

  filters = pr_jot_filters_create(p, text,
    PR_JOT_FILTER_TYPE_COMMANDS_WITH_CLASSES, 0);
  if (filters != NULL) {
    (void) pr_jot_filters_destroy(filters);
  }

  destroy_pool(p);
  free(text);
  return 0;
}

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

/*
 * Fuzz the FTP command line parsing path: bytes -> tokenized cmd_rec ->
 * recognition predicates (HTTP/SMTP/SSH2 sniff, FTP id lookup, displayable
 * string, errno-cache, stash compare against all known verbs). This is what
 * runs for every line a remote client sends before any auth decision.
 *
 * We deliberately stop short of pr_cmd_dispatch_phase: full dispatch reaches
 * for session.c streams, scoreboard, proctitle and the response queues, and
 * many module handlers gate on auth state that can't be faithfully stubbed
 * from outside a real session without re-implementing fork_server. The
 * recognition path is the attacker-controlled pre-auth slice, which is what
 * we want exercised here.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "conf.h"
#include "cmd.h"
#include "ftp.h"
#include "stash.h"
#include "regexp.h"
#include "netaddr.h"

extern void init_inet(void);

static int initialized = 0;

static unsigned int tokenize(char *buf, char **argv, unsigned int max) {
  unsigned int argc = 0;
  char *p = buf;

  while (*p && argc < max) {
    while (*p && isspace((unsigned char) *p)) {
      *p++ = '\0';
    }
    if (*p == '\0') break;
    argv[argc++] = p;
    while (*p && !isspace((unsigned char) *p)) {
      p++;
    }
  }
  argv[argc] = NULL;
  return argc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pool *p;
  char *buf;
  char *argv[7];
  cmd_rec *cmd;
  unsigned int argc;
  size_t len;

  if (size < 1 || size > 2048) {
    return 0;
  }

  if (!initialized) {
    init_pools();
    init_regexp();
    init_inet();
    init_netaddr();
    init_stash();
    initialized = 1;
  }

  buf = malloc(size + 1);
  if (buf == NULL) return 0;
  memcpy(buf, data, size);
  buf[size] = '\0';

  p = make_sub_pool(NULL);
  if (p == NULL) {
    free(buf);
    return 0;
  }

  /* Cap at 6; pr_cmd_alloc's vararg is only invoked with up to 6 below. */
  argc = tokenize(buf, argv, 6);
  if (argc == 0) {
    destroy_pool(p);
    free(buf);
    return 0;
  }

  switch (argc) {
    case 1: cmd = pr_cmd_alloc(p, 1, pstrdup(p, argv[0])); break;
    case 2: cmd = pr_cmd_alloc(p, 2, pstrdup(p, argv[0]), pstrdup(p, argv[1]));
            break;
    case 3: cmd = pr_cmd_alloc(p, 3, pstrdup(p, argv[0]), pstrdup(p, argv[1]),
              pstrdup(p, argv[2])); break;
    case 4: cmd = pr_cmd_alloc(p, 4, pstrdup(p, argv[0]), pstrdup(p, argv[1]),
              pstrdup(p, argv[2]), pstrdup(p, argv[3])); break;
    case 5: cmd = pr_cmd_alloc(p, 5, pstrdup(p, argv[0]), pstrdup(p, argv[1]),
              pstrdup(p, argv[2]), pstrdup(p, argv[3]), pstrdup(p, argv[4]));
            break;
    default:
      cmd = pr_cmd_alloc(p, 6, pstrdup(p, argv[0]), pstrdup(p, argv[1]),
              pstrdup(p, argv[2]), pstrdup(p, argv[3]), pstrdup(p, argv[4]),
              pstrdup(p, argv[5])); break;
  }

  if (cmd != NULL) {
    (void) pr_cmd_get_id(cmd->argv[0]);
    (void) pr_cmd_is_http(cmd);
    (void) pr_cmd_is_smtp(cmd);
    (void) pr_cmd_is_ssh2(cmd);
    (void) pr_cmd_strcmp(cmd, argv[0]);
    (void) pr_cmd_get_displayable_str(cmd, &len);
    (void) pr_cmd_clear_cache(cmd);
    (void) pr_cmd_set_errno(cmd, 0);
    (void) pr_cmd_get_errno(cmd);

    /* Walk the command stash for every known FTP verb id. */
    {
      static const int ids[] = {
        PR_CMD_USER_ID, PR_CMD_PASS_ID, PR_CMD_ACCT_ID, PR_CMD_CWD_ID,
        PR_CMD_CDUP_ID, PR_CMD_SMNT_ID, PR_CMD_REIN_ID, PR_CMD_QUIT_ID,
        PR_CMD_PORT_ID, PR_CMD_PASV_ID, PR_CMD_TYPE_ID, PR_CMD_STRU_ID,
        PR_CMD_MODE_ID, PR_CMD_RETR_ID, PR_CMD_STOR_ID, PR_CMD_STOU_ID,
        PR_CMD_APPE_ID, PR_CMD_ALLO_ID, PR_CMD_REST_ID, PR_CMD_RNFR_ID,
        PR_CMD_RNTO_ID, PR_CMD_ABOR_ID, PR_CMD_DELE_ID, PR_CMD_RMD_ID,
        PR_CMD_MKD_ID, PR_CMD_PWD_ID,  PR_CMD_LIST_ID, PR_CMD_NLST_ID,
        PR_CMD_SITE_ID, PR_CMD_SYST_ID, PR_CMD_STAT_ID, PR_CMD_HELP_ID,
        PR_CMD_NOOP_ID, PR_CMD_FEAT_ID, PR_CMD_OPTS_ID, PR_CMD_AUTH_ID,
        PR_CMD_PBSZ_ID, PR_CMD_PROT_ID, PR_CMD_EPRT_ID, PR_CMD_EPSV_ID,
        PR_CMD_HOST_ID, PR_CMD_RANG_ID, PR_CMD_CLNT_ID,
      };
      unsigned int i;
      for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        (void) pr_cmd_cmp(cmd, ids[i]);
      }
    }
  }

  destroy_pool(p);
  free(buf);
  return 0;
}

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

#include <sys_defs.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <vstring.h>
#include <valid_hostname.h>
#include <stringops.h>

#include "quote_822_local.h"
#include "quote_821_local.h"
#include "quote_flags.h"
#include "valid_mailhost_addr.h"
#include "ehlo_mask.h"
#include "dsn_util.h"
#include "split_addr.h"
#include "mail_params.h"
#include "mail_addr_form.h"
#include "fold_addr.h"
#include <argv.h>
#include <mymalloc.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    /* split_addr_internal reads var_double_bounce_sender and var_ownreq_special,
       which mail_conf_read() normally sets. Seed with the documented defaults. */
    if (var_double_bounce_sender == NULL)
        var_double_bounce_sender = mystrdup(DEF_DOUBLE_BOUNCE);
    var_ownreq_special = DEF_OWNREQ_SPECIAL;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 4096)
        return 0;
    char *buf = (char *) malloc(size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    VSTRING *out = vstring_alloc(64);

    /* RFC 822 quote/unquote of local part. */
    (void) quote_822_local_flags(out, buf, QUOTE_FLAG_DEFAULT);
    (void) quote_822_local_flags(out, buf, QUOTE_FLAG_8BITCLEAN | QUOTE_FLAG_APPEND);
    (void) unquote_822_local(out, buf);

    /* RFC 821 quote of local part. */
    (void) quote_821_local_flags(out, buf, QUOTE_FLAG_8BITCLEAN);
    (void) quote_821_local_flags(out, buf, QUOTE_FLAG_DEFAULT);

    /* Hostname / address validation. */
    (void) valid_hostname(buf, DONT_GRIPE);
    (void) valid_hostaddr(buf, DONT_GRIPE);
    (void) valid_ipv4_hostaddr(buf, DONT_GRIPE);
    (void) valid_ipv6_hostaddr(buf, DONT_GRIPE);
    (void) valid_hostport(buf, DONT_GRIPE);
    (void) valid_mailhost_addr(buf, DONT_GRIPE);
    (void) valid_mailhost_literal(buf, DONT_GRIPE);

    /* split_addr: split user+ext into user and ext. */
    {
        char *dup = mystrdup(buf);
        (void) split_addr(dup, "+");
        myfree(dup);
    }

    /* DSN validation/splitting. */
    {
        DSN_SPLIT dp;
        (void) dsn_valid(buf);
        (void) dsn_split(&dp, "4.0.0", buf);
    }

    /* EHLO mask parsing. */
    (void) ehlo_mask(buf);

    /* mail_parm_split calls extpar with msg_fatal on syntax error and
       mail_addr_crunch_opt requires a running rewrite daemon — skip both. */

    /* fold_addr: case-fold address according to flags. */
    {
        VSTRING *fold = vstring_alloc(32);
        (void) fold_addr(fold, buf, FOLD_ADDR_ALL);
        (void) fold_addr(fold, buf, FOLD_ADDR_HOST);
        (void) fold_addr(fold, buf, FOLD_ADDR_USER);
        vstring_free(fold);
    }

    /* mail_addr_form_from_string: parse internal/external/etc. name. */
    (void) mail_addr_form_from_string(buf);

    vstring_free(out);
    free(buf);
    return 0;
}

/* Copyright 2021 Google LLC
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
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <mymalloc.h>
#include <msg.h>
#include <vstring.h>

#include <rec_type.h>
#include <is_header.h>
#include <header_opts.h>
#include <mail_params.h>
#include <header_token.h>
#include <lex_822.h>
#include <mime_state.h>

#include <stringops.h>
#include <vstream.h>
#include <msg_vstream.h>
#include <rec_streamlf.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    /* mime_state_update -> header_opts_find -> header_drop_init reads
       var_drop_hdrs, which mail_conf_read() normally sets. */
    if (var_drop_hdrs == NULL)
        var_drop_hdrs = mystrdup(DEF_DROP_HDRS);
    return 0;
}

/* Empty MIME callbacks; we exercise the parser, not the output. */
static void head_out(void *context, int class, const HEADER_OPTS *unused_info,
                     VSTRING *buf, off_t offset) {
    (void) context; (void) class; (void) unused_info; (void) buf; (void) offset;
}
static void head_end(void *context) { (void) context; }
static void body_end(void *context) { (void) context; }
static void err_print(void *unused_context, int err_flag, const char *text,
                      ssize_t len) {
    (void) unused_context; (void) err_flag; (void) text; (void) len;
}
static void body_out(void *context, int rec_type, const char *buf, ssize_t len,
                     off_t offset) {
    (void) context; (void) rec_type; (void) buf; (void) len; (void) offset;
}

#define MIME_OPTIONS                                                           \
    (MIME_OPT_REPORT_8BIT_IN_7BIT_BODY | MIME_OPT_REPORT_8BIT_IN_HEADER |      \
     MIME_OPT_REPORT_ENCODING_DOMAIN | MIME_OPT_REPORT_TRUNC_HEADER |          \
     MIME_OPT_REPORT_NESTING | MIME_OPT_DOWNGRADE)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536)
        return 0;

    msg_vstream_init("fuzz_mime", VSTREAM_OUT);
    MIME_STATE *state = mime_state_alloc(MIME_OPTIONS, head_out, head_end,
                                         body_out, body_end, err_print,
                                         (void *) VSTREAM_OUT);

    /* Walk the input as newline-separated records — the format that
       cleanup_message.c hands mime_state_update in production.
       Lines that exceed REC_LIMIT are split into CONT records. */
    const unsigned char *p = data;
    const unsigned char *end = data + size;
    while (p < end) {
        const unsigned char *nl = memchr(p, '\n', end - p);
        const unsigned char *line_end = nl ? nl : end;
        ssize_t len = line_end - p;

        int rec_type;
        if (len > 0 && p[len - 1] == '\r')
            len--;

        if (nl == NULL) {
            /* Trailing partial line: treat as continuation so the state
               machine sees more content forms. */
            rec_type = REC_TYPE_CONT;
        } else {
            rec_type = REC_TYPE_NORM;
        }
        (void) mime_state_update(state, rec_type, (const char *) p, len);
        if (nl == NULL)
            break;
        p = nl + 1;
    }

    /* End of message marker exercises the final-state code paths. */
    (void) mime_state_update(state, REC_TYPE_END, "", 0);

    mime_state_free(state);
    return 0;
}

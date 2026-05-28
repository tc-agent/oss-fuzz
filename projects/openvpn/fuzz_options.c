/* Copyright 2026 fuzz-for-me contributors
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

#include "config.h"
#include "syshead.h"
#include "options.h"
#include "options_util.h"
#include "buffer.h"
#include "error.h"
#include "env_set.h"
#include "init.h"
#include "manage.h"

#include <setjmp.h>

/* error.c is patched at build time so that openvpn_exit() / usage_small() in
 * x_msg_va call fuzz_exit_longjmp() before the real exit; the harness then
 * longjmps back out of read_config_string()/options_postprocess(). Without
 * this, attacker-controlled M_FATAL/M_USAGE paths would kill the fuzzer
 * process. Weak no-op defaults live in error.c; we override them. */
int fuzz_in_test = 0;
static jmp_buf fuzz_exit_jmp;

void fuzz_exit_longjmp(int status)
{
    (void)status;
    fuzz_in_test = 0;
    longjmp(fuzz_exit_jmp, 1);
}

/* Run one parser entry on a fresh options struct.  Each entry exercises a
 * distinct path through add_option(): configs vs. pulled-from-server options
 * vs. argv command line.  Splitting them keeps state isolated and lets
 * libFuzzer hill-climb each independently. */
static void run_config_string(const uint8_t *data, size_t size)
{
    char *config = (char *)malloc(size + 1);
    if (!config)
    {
        return;
    }
    memcpy(config, data, size);
    config[size] = '\0';

    struct options options;
    struct gc_arena gc_setup = gc_new();
    struct env_set *es = env_set_create(&gc_setup);
    uint64_t option_types_found = 0;

    init_options(&options);

    if (setjmp(fuzz_exit_jmp) == 0)
    {
        fuzz_in_test = 1;
        read_config_string("[FUZZ]", &options, config,
                           M_WARN, OPT_P_DEFAULT,
                           &option_types_found, es);

        /* Drive the validation/mutation passes: helper_*, cipher selection,
         * connection-list expansion, file checks. ~1700 extra lines of
         * options.c + helper.c logic. */
        options_postprocess(&options, es);

        /* Walk every option and push it into the env_set. Exercises
         * setenv_str/_int/_str_i plus connection-list iteration. */
        setenv_settings(es, &options);

        /* Force the verbose dump that prints every option through
         * x_msg_va. options.verbosity=11 keeps msg() from filtering at
         * D_SHOW_PARMS so each SHOW_* macro executes. */
        struct options shown = options;
        shown.verbosity = 11;
        show_settings(&shown);

    }
    fuzz_in_test = 0;

    uninit_options(&options);
    env_set_destroy(es);
    gc_free(&gc_setup);
    free(config);
}

static void run_push_options(const uint8_t *data, size_t size)
{
    struct options options;
    struct gc_arena gc_setup = gc_new();
    struct env_set *es = env_set_create(&gc_setup);
    uint64_t option_types_found = 0;

    init_options(&options);

    /* apply_push_options walks a comma-separated list, so we feed it a
     * normalized copy of the input. */
    struct buffer buf = alloc_buf_gc(size + 1, &gc_setup);
    buf_write(&buf, data, size);

    struct context c;
    memset(&c, 0, sizeof(c));
    c.options = options;
    c.es = es;

    if (setjmp(fuzz_exit_jmp) == 0)
    {
        fuzz_in_test = 1;
        apply_push_options(&c, &c.options, &buf,
                           OPT_P_DEFAULT, &option_types_found, es, false);
    }
    fuzz_in_test = 0;

    uninit_options(&c.options);
    env_set_destroy(es);
    gc_free(&gc_setup);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536)
    {
        return 0;
    }

    /* Single-byte selector at front lets libFuzzer toggle entry points. */
    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;
    if (payload_size == 0)
    {
        return 0;
    }

    switch (selector & 0x1)
    {
        case 0:
            run_config_string(payload, payload_size);
            break;
        case 1:
            run_push_options(payload, payload_size);
            break;
    }

    return 0;
}

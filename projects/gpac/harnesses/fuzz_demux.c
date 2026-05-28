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
 */
/*
 * Extension-aware demux/parse fuzz harness for GPAC.
 *
 * The upstream fuzz_probe_analyze harness writes the input to an
 * extension-less path, so GPAC's text/scene source filters (BIFS, XMT,
 * SVG, X3D, MPD, HLS, subtitles, ...) — which are selected by file
 * extension — are never exercised. This harness derives a file extension
 * from the first input byte, covering those formats too.
 *
 * The whole file is fed through a full GPAC filter session terminated by
 * the "inspect" filter, exactly as the reproducer command-line would.
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include <gpac/filters.h>
#include <gpac/constants.h>

/* Keep in sync with EXTS in gen_fuzz_seeds.py. */
static const char *exts[] = {
    "mp4", "mov", "m4a", "3gp", "heif", "avif", "mj2", "ismv", "ismt", "iamf",
    "ts", "m2ts", "mkv", "webm", "avi", "flv", "ogg", "mpg", "vob",
    "mp3", "aac", "ac3", "amr", "flac", "wav", "qcp", "aif", "dts", "au",
    "h264", "h265", "av1", "obu", "ivf", "cmp", "m4v", "m1v", "vvc",
    "jpg", "png", "bmp", "gif", "jp2",
    "bt", "xmt", "wrl", "x3d", "x3dv", "svg", "swf", "saf",
    "mpd", "m3u8",
    "srt", "vtt", "ttml", "sub", "ttxt", "ssa",
    "nhml", "nhnt", "gsf", "sdp"
};

static GF_FilterSession *g_fs;
static volatile int g_done;

static void *watchdog(void *arg)
{
    int i;
    for (i = 0; i < 100 && !g_done; i++)
        usleep(100000);
    if (!g_done && g_fs)
        gf_fs_abort(g_fs, GF_FS_FLUSH_NONE);
    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char filename[256];
    GF_Err e;
    pthread_t wd;
    GF_Filter *src;

    if (size < 2)
        return 0;

    unsigned idx = data[0] % (sizeof(exts) / sizeof(exts[0]));
    data++;
    size--;

    sprintf(filename, "/tmp/fzd_%d.%s", getpid(), exts[idx]);
    FILE *fp = fopen(filename, "wb");
    if (!fp)
        return 0;
    fwrite(data, size, 1, fp);
    fclose(fp);

    gf_log_set_tool_level(GF_LOG_ALL, GF_LOG_QUIET);

    GF_FilterSession *fs = gf_fs_new_defaults(0);
    if (!fs) {
        unlink(filename);
        return 0;
    }

    g_fs = fs;
    g_done = 0;
    pthread_create(&wd, NULL, watchdog, NULL);

    src = gf_fs_load_source(fs, filename, NULL, NULL, &e);
    if (src) {
        gf_fs_load_filter(fs, "inspect:deep:analyze=bs", &e);
        gf_fs_run(fs);
    }

    g_done = 1;
    pthread_join(wd, NULL);
    g_fs = NULL;

    gf_fs_del(fs);
    unlink(filename);
    return 0;
}

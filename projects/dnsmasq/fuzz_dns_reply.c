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
 * Drives the "DNS reply from upstream" code path:
 *   - forward.c::process_reply  (un-static'd at build time)
 *   - dnssec.c::dnssec_validate_reply  (only if HAVE_DNSSEC)
 *
 * Both functions take a synthesized response packet that an attacker
 * controlling an upstream server (or an on-path MITM) could send.
 */

#include "fuzz_header.h"

/* process_reply is normally static in forward.c; un-static'd in build.sh. */
size_t process_reply(struct dns_header *header, time_t now, struct server *server,
                     size_t n, int check_rebind, int no_cache, int cache_secure,
                     int bogusanswer, int ad_reqd, int do_bit, int added_pheader,
                     union mysockaddr *query_source, unsigned char *limit, int ede);

#ifdef HAVE_DNSSEC
/* dnssec_validate_reply lazily allocates daemon->rr_status via whine_malloc.
   It's not tracked by the harness's GC, so free it here to avoid OOM. */
static void free_dnssec_state(void) {
  if (daemon->rr_status) {
    free(daemon->rr_status);
    daemon->rr_status = NULL;
    daemon->rr_status_sz = 0;
  }
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 1) return 0;

  gb_init();

  int selector = (int)data[0];
  data += 1; size -= 1;

  if (init_daemon(&data, &size) != 0) goto cleanup;

  cache_init();
  blockdata_init();

  /* Fields process_reply/dnssec_validate_reply read on top of init_daemon */
  daemon->packet_buff_sz = 8192;
  daemon->packet = (char *)gb_alloc_data(daemon->packet_buff_sz);
  daemon->edns_pktsz = 4096;
  daemon->keyname = (char *)gb_alloc_data(MAXDNAME * 4);
  daemon->cname = (char *)gb_alloc_data(MAXDNAME * 4);
  if (!daemon->packet || !daemon->keyname || !daemon->cname) goto cleanup;

  if (size < sizeof(struct dns_header) + 16) goto cleanup;

  /* Copy the fuzz payload into a buffer with NAME_ESCAPE headroom. */
  size_t buf_sz = size + 256;
  char *pkt = (char *)malloc(buf_sz);
  if (!pkt) goto cleanup;
  memset(pkt, 0, buf_sz);
  memcpy(pkt, data, size);
  pointer_arr[pointer_idx++] = (void *)pkt;
  struct dns_header *header = (struct dns_header *)pkt;

  /* Selector chooses which entry point to hit; both run for selector==2. */
  int do_process = (selector & 1) == 0;
  int do_dnssec  = (selector & 2) != 0;

  if (do_process) {
    struct server srv;
    memset(&srv, 0, sizeof(srv));
    srv.addr.sa.sa_family = AF_INET;
    union mysockaddr qsrc;
    memset(&qsrc, 0, sizeof(qsrc));
    qsrc.sa.sa_family = AF_INET;

    /* limit pointer must be past the packet end; allocate that way above. */
    process_reply(header, /*now=*/0, &srv, size,
                  /*check_rebind=*/0, /*no_cache=*/1, /*cache_secure=*/0,
                  /*bogusanswer=*/0, /*ad_reqd=*/0, /*do_bit=*/0,
                  /*added_pheader=*/0, &qsrc,
                  (unsigned char *)(pkt + buf_sz), /*ede=*/EDE_UNSET);
  }

#ifdef HAVE_DNSSEC
  if (do_dnssec) {
    /* extract_name's NAME_ESCAPE writes 2 bytes per source byte, so any
       buffer it fills needs MAXDNAME * 2 + slack. */
    char *keyname = (char *)malloc(MAXDNAME * 4);
    if (!keyname) goto cleanup;
    pointer_arr[pointer_idx++] = (void *)keyname;
    keyname[0] = '\0';

    int klass = 1, neganswer = 0, prim_ok = 0, nons = 0, neg_ttl = 0;
    int vc = 1000;
    dnssec_validate_reply(/*now=*/0, header, size, daemon->namebuff,
                          keyname, &klass, /*check_unsigned=*/0,
                          &neganswer, &prim_ok, &nons, &neg_ttl, &vc);
    int vc2 = 1000;
    dnssec_validate_by_ds(/*now=*/0, header, size, daemon->namebuff,
                          keyname, klass, &vc2);
    int vc3 = 1000;
    dnssec_validate_ds(/*now=*/0, header, size, daemon->namebuff,
                       keyname, klass, &vc3);
    free_dnssec_state();
  }
#endif

  cache_start_insert();
  fuzz_blockdata_cleanup();

cleanup:
  gb_cleanup();
  return 0;
}

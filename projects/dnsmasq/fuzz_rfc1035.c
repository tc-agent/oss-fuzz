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

#include "fuzz_header.h"

/*
 *  Targets "extract_addresses"
 */
void FuzzExtractTheAddress(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  /* Consume MAXDNAME bytes of fuzz input via the GC-tracked helper, then
     allocate a larger scratch buffer for extract_name (NAME_ESCAPE doubles
     output length). */
  if (gb_get_len_null_terminated(&data, &size, MAXDNAME) == NULL) return;
  char *new_name = (char *)malloc(MAXDNAME * 4);
  if (!new_name) return;
  pointer_arr[pointer_idx++] = (void*)new_name;
  new_name[0] = 'a'; new_name[1] = '\0';

  int is_sign = get_int(&data, &size);
  int check_rebind = get_int(&data, &size);
  int secure =  get_int(&data, &size);

  if (size > (sizeof(struct dns_header) +50)) {
    char *new_data = malloc(size);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    pointer_arr[pointer_idx++] = (void*)new_data;

    time_t now = 0;
    extract_addresses((struct dns_header *)new_data, size, new_name, now, NULL, NULL, check_rebind, 0, secure);
    (void)is_sign;
  }
}


/*
 * Targets "answer_request"
 */
void FuzzAnswerTheRequest(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  struct in_addr local_addr;
  struct in_addr local_netmask;
  time_t now;

  int i1 = get_int(&data, &size);
  int i2 = get_int(&data, &size);
  int i3 = get_int(&data, &size);

  if (size > (sizeof(struct dns_header) +50)) {
    char *new_data = malloc(size);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    pointer_arr[pointer_idx++] = (void*)new_data;

    int stale = 0, filtered = 0;
    answer_request((struct dns_header *)new_data, new_data+size, size, local_addr, local_netmask, now, i1, i2, i3, &stale, &filtered);
  }

}

/*
 * Targets "check_for_ignored_address"
 */
void FuzzIgnoredAddress(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  if (size > (sizeof(struct dns_header) +50)) {
    //return 0;
    char *new_data = malloc(size);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    pointer_arr[pointer_idx++] = (void*)new_data;

    check_for_ignored_address((struct dns_header *)new_data, size);
  }
}

/*
 * Targets "check_for_local_domain"
 */
void FuzzCheckLocalDomain(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  
    char *new_data = malloc(size+1);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    new_data[size] = '\0';
    pointer_arr[pointer_idx++] = (void*)new_data;

    time_t now;
    check_for_local_domain(new_data, now);
}

/*
 * Targets "extract_request"
 */
void FuzzExtractRequest(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  char *new_name = NULL;
  new_name = get_len_null_terminated(&data, &size, MAXDNAME);

  if (new_name == NULL) {
    return ;
  }
  pointer_arr[pointer_idx++] = (void*)new_name;

  if (size > (sizeof(struct dns_header) +50)) {
    char *new_data = malloc(size+1);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    new_data[size] = '\0';
    pointer_arr[pointer_idx++] = (void*)new_data;

    unsigned short typeb;
    unsigned short class2b;
    extract_request((struct dns_header *)new_data, size, new_name, &typeb, &class2b);
  }
}


/*
 * Targets "in_arpa_name_2_addr"
 */
void FuzzArpaName2Addr(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  char *new_name = NULL;
  new_name = get_null_terminated(&data, &size);

  if (new_name == NULL) {
    return ;
  }
  pointer_arr[pointer_idx++] = (void*)new_name;
  union all_addr addr;
  in_arpa_name_2_addr(new_name, &addr);
  return;
}

void FuzzResizePacket(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  char *new_packet = malloc(50);
  if (new_packet == NULL) return;

  if (size > (sizeof(struct dns_header) + 50)) {
    /* resize_packet's memmove can append up to hlen (50) bytes past the
       answer section, so allocate the dns_header buffer with that headroom. */
    size_t buf_sz = size + 64;
    char *new_data = malloc(buf_sz);
    memset(new_data, 0, buf_sz);
    memcpy(new_data, data, size);
    pointer_arr[pointer_idx++] = (void*)new_data;

    resize_packet((struct dns_header *)new_data, size, (unsigned char*)new_packet, 50);
  }
  free(new_packet);
}

void FuzzSetupReply(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;
  
  if (size > (sizeof(struct dns_header) + 50)) {
    char *new_data = malloc(size+1);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    new_data[size] = '\0';
    pointer_arr[pointer_idx++] = (void*)new_data;

    setup_reply((struct dns_header *)new_data, 0, 0);
  }
}


void FuzzCheckForBogusWildcard(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  /* check_for_bogus_wildcard re-extracts the name into the provided buffer
     via extract_name, which can write up to ~2x bytes via NAME_ESCAPE. Use
     a large scratch buffer instead of the MAXDNAME-sized fuzz string. */
  if (gb_get_len_null_terminated(&data, &size, MAXDNAME) == NULL) {
    return;
  }
  char *nname = (char *)malloc(MAXDNAME * 4);
  if (!nname) return;
  pointer_arr[pointer_idx++] = (void *)nname;
  nname[0] = 'a';
  nname[1] = '\0';

  if (size > (sizeof(struct dns_header) + 50)) {
    char *new_data = malloc(size+1);
    memset(new_data, 0, size);
    memcpy(new_data, data, size);
    new_data[size] = '\0';
    pointer_arr[pointer_idx++] = (void*)new_data;

    time_t now = 0;
    check_for_bogus_wildcard((struct dns_header *)new_data, size, nname, now);
  }
}


/*
 * Fuzzer entrypoint.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  daemon = NULL;
  if (size < 1) {
    return 0;
  }

  gb_init();

  int i = (int)data[0];
  data += 1;
  size -= 1;

  int succ = init_daemon(&data, &size);

  if (succ == 0) {
    cache_init();
    blockdata_init();

#define TS 9
    int t = i % TS;
    if (t == 0)       FuzzExtractTheAddress(&data, &size);
    else if (t == 1)  FuzzAnswerTheRequest(&data, &size);
    else if (t == 2)  FuzzCheckLocalDomain(&data, &size);
    else if (t == 3)  FuzzExtractRequest(&data, &size);
    else if (t == 4)  FuzzArpaName2Addr(&data, &size);
    else if (t == 5)  FuzzResizePacket(&data, &size);
    else if (t == 6)  FuzzSetupReply(&data, &size);
    else if (t == 7)  FuzzCheckForBogusWildcard(&data, &size);
    else              FuzzIgnoredAddress(&data, &size);

    cache_start_insert();
    fuzz_blockdata_cleanup();
  }

  gb_cleanup();
  return 0;
}

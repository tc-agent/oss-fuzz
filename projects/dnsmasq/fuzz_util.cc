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

extern "C" {
#include "dnsmasq.h"
}

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define STR_SIZE 75

static int init_daemon(FuzzedDataProvider &provider,
                       std::vector<void *> &allocs,
                       std::vector<std::string> &strings) {
  auto alloc = [&](size_t sz) -> void * {
    void *p = calloc(1, sz);
    if (p) allocs.push_back(p);
    return p;
  };

  auto make_string = [&](size_t max_len) -> char * {
    strings.push_back(provider.ConsumeRandomLengthString(max_len));
    // Guarantee strlen > 0 so daemon-> fields don't trip dnsmasq helpers
    // that walk past the NUL terminator on empty input.
    if (strings.back().empty() || strings.back()[0] == '\0') {
      strings.back() = "a";
    }
    return strings.back().data();
  };

  // Allocate daemon separately (not via alloc) so it can be freed last.
  // dnsmasq's free_real() dereferences daemon for metrics tracking.
  daemon = (struct daemon *)calloc(1, sizeof(struct daemon));
  if (!daemon) return -1;

  daemon->max_ttl = provider.ConsumeIntegral<int>();
  daemon->neg_ttl = provider.ConsumeIntegral<int>();
  daemon->local_ttl = provider.ConsumeIntegral<int>();
  daemon->min_cache_ttl = provider.ConsumeIntegral<int>();

  daemon->namebuff = make_string(MAXDNAME);

  // daemon->naptr
  struct naptr *naptr_ptr = (struct naptr *)alloc(sizeof(struct naptr));
  if (!naptr_ptr) return -1;
  naptr_ptr->name = make_string(STR_SIZE);
  naptr_ptr->replace = make_string(STR_SIZE);
  naptr_ptr->regexp = make_string(STR_SIZE);
  naptr_ptr->services = make_string(STR_SIZE);
  naptr_ptr->flags = make_string(STR_SIZE);
  daemon->naptr = naptr_ptr;

  // daemon->int_names
  struct interface_name *int_namses =
      (struct interface_name *)alloc(sizeof(struct interface_name));
  if (!int_namses) return -1;
  int_namses->name = make_string(STR_SIZE);
  int_namses->intr = make_string(STR_SIZE);

  struct addrlist *d_addrlist = (struct addrlist *)alloc(sizeof(struct addrlist));
  if (!d_addrlist) return -1;
  d_addrlist->flags = provider.ConsumeIntegral<int>();
  d_addrlist->prefixlen = provider.ConsumeIntegral<int>();
  int_namses->addr = d_addrlist;
  daemon->int_names = int_namses;

  // daemon->addrbuf
  char *adbuf = (char *)alloc(200);
  if (!adbuf) return -1;
  daemon->addrbuff = adbuf;

  // daemon->auth_zones
  struct auth_zone *d_az = (struct auth_zone *)alloc(sizeof(struct auth_zone));
  if (!d_az) return -1;
  d_az->domain = make_string(STR_SIZE);
  daemon->auth_zones = d_az;

  // daemon->mxnames
  struct mx_srv_record *mx_srv_rec =
      (struct mx_srv_record *)alloc(sizeof(struct mx_srv_record));
  if (!mx_srv_rec) return -1;
  mx_srv_rec->next = daemon->mxnames;
  daemon->mxnames = mx_srv_rec;
  mx_srv_rec->name = make_string(STR_SIZE);
  mx_srv_rec->target = make_string(STR_SIZE);
  mx_srv_rec->issrv = provider.ConsumeIntegral<int>();
  mx_srv_rec->weight = provider.ConsumeIntegral<int>();
  mx_srv_rec->priority = provider.ConsumeIntegral<int>();
  mx_srv_rec->srvport = provider.ConsumeIntegral<int>();

  // daemon->txt
  struct txt_record *txt_record =
      (struct txt_record *)alloc(sizeof(struct txt_record));
  if (!txt_record) return -1;
  txt_record->name = make_string(STR_SIZE);
  txt_record->txt = (unsigned char *)make_string(STR_SIZE);
  txt_record->class2 = provider.ConsumeIntegralInRange<short>(0, 9);
  daemon->txt = txt_record;

  // daemon->rr
  struct txt_record *rr_record =
      (struct txt_record *)alloc(sizeof(struct txt_record));
  if (!rr_record) return -1;
  rr_record->name = make_string(STR_SIZE);
  rr_record->txt = (unsigned char *)make_string(STR_SIZE);
  rr_record->class2 = provider.ConsumeIntegralInRange<short>(0, 9);
  daemon->rr = rr_record;

  // daemon->relay4
  struct dhcp_relay *dr = (struct dhcp_relay *)alloc(sizeof(struct dhcp_relay));
  if (!dr) return -1;
  dr->interface = make_string(STR_SIZE);
  dr->next = NULL;
  daemon->relay4 = dr;

  // daemon->bridges
  struct dhcp_bridge *db = (struct dhcp_bridge *)alloc(sizeof(struct dhcp_bridge));
  if (!db) return -1;
  {
    std::string iface_str = provider.ConsumeRandomLengthString(IF_NAMESIZE - 1);
    memcpy(db->iface, iface_str.c_str(), iface_str.size() + 1);
  }

  struct dhcp_bridge *db_alias =
      (struct dhcp_bridge *)alloc(sizeof(struct dhcp_bridge));
  if (!db_alias) return -1;
  {
    std::string alias_str = provider.ConsumeRandomLengthString(IF_NAMESIZE - 1);
    memcpy(db_alias->iface, alias_str.c_str(), alias_str.size() + 1);
  }
  db->alias = db_alias;
  daemon->bridges = db;

  // daemon->if_names, if_addrs, if_except, dhcp_except, authinterface
  auto make_iname = [&]() -> struct iname * {
    struct iname *in = (struct iname *)alloc(sizeof(struct iname));
    if (!in) return nullptr;
    in->name = make_string(STR_SIZE);
    in->next = NULL;
    return in;
  };

  daemon->if_names = make_iname();
  daemon->if_addrs = make_iname();
  daemon->if_except = make_iname();
  daemon->dhcp_except = make_iname();
  daemon->authinterface = make_iname();
  if (!daemon->if_names || !daemon->if_addrs || !daemon->if_except ||
      !daemon->dhcp_except || !daemon->authinterface)
    return -1;

  // daemon->cnames
  struct cname *cn = (struct cname *)alloc(sizeof(struct cname));
  if (!cn) return -1;
  cn->alias = make_string(STR_SIZE);
  cn->target = make_string(STR_SIZE);
  daemon->cnames = cn;

  // daemon->ptr
  struct ptr_record *ptr = (struct ptr_record *)alloc(sizeof(struct ptr_record));
  if (!ptr) return -1;
  ptr->name = make_string(STR_SIZE);
  daemon->ptr = ptr;

  // daemon->dhcp
  struct dhcp_context *dhcp_c =
      (struct dhcp_context *)alloc(sizeof(struct dhcp_context));
  if (!dhcp_c) return -1;
  dhcp_c->next = NULL;
  dhcp_c->current = NULL;
  struct dhcp_netid *dhcp_c_netid =
      (struct dhcp_netid *)alloc(sizeof(struct dhcp_netid));
  if (!dhcp_c_netid) return -1;
  dhcp_c_netid->net = make_string(STR_SIZE);
  dhcp_c->filter = dhcp_c_netid;
  dhcp_c->template_interface = make_string(STR_SIZE);
  daemon->dhcp = dhcp_c;

  // daemon->dhcp6
  struct dhcp_context *dhcp6_c =
      (struct dhcp_context *)alloc(sizeof(struct dhcp_context));
  if (!dhcp6_c) return -1;
  dhcp6_c->next = NULL;
  dhcp6_c->current = NULL;
  struct dhcp_netid *dhcp6_c_netid =
      (struct dhcp_netid *)alloc(sizeof(struct dhcp_netid));
  if (!dhcp6_c_netid) return -1;
  dhcp6_c_netid->net = make_string(STR_SIZE);
  dhcp6_c->filter = dhcp6_c_netid;
  dhcp6_c->template_interface = make_string(STR_SIZE);
  daemon->dhcp6 = dhcp6_c;

  daemon->doing_dhcp6 = 1;

  // daemon->dhcp_buffs
  daemon->dhcp_buff = (char *)alloc(DHCP_BUFF_SZ);
  daemon->dhcp_buff2 = (char *)alloc(DHCP_BUFF_SZ);
  daemon->dhcp_buff3 = (char *)alloc(DHCP_BUFF_SZ);
  if (!daemon->dhcp_buff || !daemon->dhcp_buff2 || !daemon->dhcp_buff3)
    return -1;

  // daemon->ignore_addr
  struct bogus_addr *bb = (struct bogus_addr *)alloc(sizeof(struct bogus_addr));
  if (!bb) return -1;
  daemon->ignore_addr = bb;

  // daemon->doctors
  struct doctor *doctors = (struct doctor *)alloc(sizeof(struct doctor));
  if (!doctors) return -1;
  doctors->next = NULL;
  daemon->doctors = doctors;

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider provider(data, size);

  std::vector<void *> allocs;
  std::vector<std::string> strings;
  strings.reserve(40);

  int succ = init_daemon(provider, allocs, strings);
  if (succ == 0) {
    std::string t1_str = provider.ConsumeRandomLengthString(MAXDNAME);
    std::string t2_str = provider.ConsumeRandomLengthString(MAXDNAME);
    if (t1_str.empty() || t2_str.empty())
      goto cleanup;
    // dnsmasq's hostname_issubdomain reads one byte before the buffer when
    // passed a zero-length C string; check_name and parse_hex also mutate
    // their inputs in-place. Run every entry point on a fresh copy so one
    // call's mutation can't poison the next.
    auto run_with_copy = [](char *src, auto &&fn) {
      if (!src) return;
      size_t n = strlen(src);
      if (n == 0) return;
      char *buf = (char *)malloc(n + 1);
      if (!buf) return;
      memcpy(buf, src, n + 1);
      fn(buf);
      free(buf);
    };

    char *t1 = t1_str.data();
    char *t2 = t2_str.data();
    if (strlen(t1) == 0 || strlen(t2) == 0)
      goto cleanup;

    run_with_copy(t1, [&](char *a) {
      run_with_copy(t2, [&](char *b) { hostname_isequal(a, b); });
    });

    run_with_copy(t1, [&](char *a) { legal_hostname(a); });
    run_with_copy(t2, [&](char *a) {
      char *tmp = canonicalise(a, NULL);
      if (tmp) free(tmp);
    });

    run_with_copy(t1, [&](char *a) {
      char *tmp_out = (char *)malloc(30);
      if (!tmp_out) return;
      int mac_type;
      parse_hex(a, (unsigned char *)tmp_out, 30, NULL, NULL);
      free(tmp_out);
    });
    run_with_copy(t1, [&](char *a) {
      char *tmp_out = (char *)malloc(30);
      if (!tmp_out) return;
      int mac_type;
      parse_hex(a, (unsigned char *)tmp_out, 30, NULL, &mac_type);
      free(tmp_out);
    });

    run_with_copy(t1, [&](char *a) {
      run_with_copy(t2, [&](char *b) { wildcard_match(a, b); });
    });
    {
      size_t n = std::min(t1_str.size(), t2_str.size());
      run_with_copy(t1, [&](char *a) {
        run_with_copy(t2, [&](char *b) { wildcard_matchn(a, b, (int)n); });
      });
    }
    run_with_copy(t1, [&](char *a) {
      run_with_copy(t2, [&](char *b) { hostname_issubdomain(a, b); });
    });

    run_with_copy(t1, [&](char *a) {
      union all_addr addr1;
      memset(&addr1, 0, sizeof(union all_addr));
      is_name_synthetic(0, a, &addr1);
    });
  }

cleanup:
  for (void *p : allocs)
    free(p);
  // Free daemon last since dnsmasq's free_real() dereferences it.
  free(daemon);
  daemon = NULL;

  return 0;
}

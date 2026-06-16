/*
 * Copyright 2026 Google LLC
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
 * Fuzz harness for the OVS userspace connection tracker.
 *
 * Feeds raw packet bytes through conntrack_execute() to exercise the TCP, UDP,
 * ICMP, and "other" protocol trackers as well as NAT and helper code.
 *
 * The conntrack context is initialised once per process and reused across
 * invocations to allow state-dependent code paths (e.g. established
 * connections) to be reached.
 */

#include <config.h>
#include "fuzzer.h"

#include "conntrack.h"
#include "dp-packet.h"
#include "fatal-signal.h"
#include "flow.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "timeval.h"

static struct conntrack *ct;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static bool initialized = false;
    if (!initialized) {
        vlog_set_verbosity("off");
        fatal_signal_init();
        ct = conntrack_init();
        initialized = true;
    }

    if (size == 0) {
        return 0;
    }

    /* Build a dp_packet from the raw fuzz bytes. */
    struct dp_packet *pkt = dp_packet_new(size);
    dp_packet_put(pkt, data, size);

    /* Mark checksums as "good" so conntrack skips software validation.
     * Without this, packets with incorrect checksums (common in fuzz input)
     * are dropped before reaching the protocol trackers in conntrack-tcp.c,
     * conntrack-icmp.c, etc.  Real OVS deployments use hardware offloading
     * which sets these flags, so bypassing validation here is realistic. */
    dp_packet_ip_checksum_set_good(pkt);
    dp_packet_l4_checksum_set_good(pkt);

    /* Determine the EtherType via flow_extract so conntrack sees a valid
     * dl_type; if the packet is malformed dl_type will be 0 and conntrack
     * will handle it gracefully. */
    struct flow flow;
    flow_extract(pkt, &flow);
    ovs_be16 dl_type = flow.dl_type;

    struct dp_packet_batch batch;
    dp_packet_batch_init_packet(&batch, pkt);

    /* Run with commit=true so we exercise connection-creation paths. */
    long long now = time_msec();
    conntrack_execute(ct, &batch, dl_type, false, true, 0,
                      NULL, NULL, NULL, NULL, now, 0);

    /* If the packet survived, run again without commit to exercise the
     * connection-lookup path. */
    if (dp_packet_batch_size(&batch) > 0) {
        pkt_metadata_init_conn(&batch.packets[0]->md);
        conntrack_execute(ct, &batch, dl_type, false, false, 0,
                          NULL, NULL, NULL, NULL, now, 0);
    }

    /* Free any surviving packets. */
    struct dp_packet *p;
    DP_PACKET_BATCH_FOR_EACH (i, p, &batch) {
        dp_packet_delete(p);
    }

    return 0;
}

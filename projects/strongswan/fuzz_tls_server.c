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

/**
 * Fuzzes the TLS server-side handshake in libtls.
 *
 * Creates a fresh TLS server context for each input and passes the fuzzer
 * data to tls->process().  This exercises:
 *   - TLS record framing (tls.c)
 *   - Handshake fragmentation and reassembly (tls_fragmentation.c)
 *   - ClientHello parsing for TLS 1.0-1.3 (tls_server.c)
 *   - Extension parsing: supported_versions, supported_groups,
 *     signature_algorithms, key_share, session_ticket, etc. (tls_server.c)
 *   - Cipher suite selection (tls_crypto.c)
 *
 * The server has no certificate configured, so the handshake will not
 * complete; we are testing the parser, not the full handshake state machine.
 *
 * Two binaries are produced by build.sh with different PLUGINS values
 * (openssl and gmp) so that both crypto back-ends are exercised.
 */

#include <library.h>
#include <utils/debug.h>
#include <tls.h>

/**
 * Minimal TLS application callback — only reached if the handshake somehow
 * completes despite the absent server certificate.  We return FAILED to
 * avoid a NULL-dereference if tls_create() were called with application=NULL
 * and the state machine reached the application-data phase.
 */
static status_t fuzz_app_process(tls_application_t *this, bio_reader_t *reader)
{
	return FAILED;
}

static status_t fuzz_app_build(tls_application_t *this, bio_writer_t *writer)
{
	return INVALID_STATE;
}

static void fuzz_app_destroy(tls_application_t *this)
{
	/* static object — nothing to free */
}

static tls_application_t fuzz_app = {
	.process = fuzz_app_process,
	.build   = fuzz_app_build,
	.destroy = fuzz_app_destroy,
};

/* Constant identities created once; tls_create() clones them, so they are
 * never consumed and can be reused across fuzzer iterations. */
static identification_t *server_id;
static identification_t *peer_id;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_tls_server");
	/* PLUGINS is defined by build.sh to either fd_plugins or fc_plugins */
	lib->plugins->load(lib->plugins, PLUGINS);
	server_id = identification_create_from_string("server@strongswan.org");
	peer_id   = identification_create_from_string("client@strongswan.org");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	tls_t *tls;

	/* Act as TLS server; the fuzzer input is treated as bytes from the client */
	tls = tls_create(TRUE /* is_server */, server_id, peer_id,
					 TLS_PURPOSE_EAP_TLS, &fuzz_app, NULL /* cache */,
					 0 /* flags */);
	if (tls)
	{
		tls->process(tls, (void *)buf, len);
		tls->destroy(tls);
	}
	return 0;
}

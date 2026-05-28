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
//
////////////////////////////////////////////////////////////////////////////////

#include "duckdb.hpp"
#include "duckdb/common/string_util.hpp"
#include <memory>
#include <string>
#include <unordered_set>

// A fresh duckdb::DuckDB rebuilds the PEG parser matcher tables from scratch
// on the first query (ParserCache lives on the DatabaseInstance), which costs
// tens of seconds per call under ASan and otherwise dominates fuzzing time —
// and can exceed the libFuzzer per-input timeout when it lands inside
// LLVMFuzzerTestOneInput. Build the instance and prime the matcher once at
// init so every fuzzed query reuses the cached matcher.
//
// NOTE: the database is shared across iterations, so catalog state (CREATE
// TABLE / CREATE INDEX / etc. that succeed) accumulates over the run. Each
// iteration uses a fresh Connection, but the DatabaseInstance — and any
// persisted catalog entries — outlives it.
static std::unique_ptr<duckdb::DuckDB> g_db;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
	g_db.reset(new duckdb::DuckDB(nullptr));
	duckdb::Connection con(*g_db);
	con.Query("SELECT 1");
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	std::string input(reinterpret_cast<const char *>(data), size);

	duckdb::Connection con(*g_db);

	std::unordered_set<std::string> internal_error_messages = {"Unoptimized Result differs from original result!",
	                                                           "INTERNAL"};
	try {
		auto result = con.Query(input);
		if (result->HasError()) {
			for (auto &internal_error : internal_error_messages) {
				if (duckdb::StringUtil::Contains(result->GetError(), internal_error)) {
					return 1;
				}
			}
		}
	} catch (std::exception &e) {
	}
	return 0;
}

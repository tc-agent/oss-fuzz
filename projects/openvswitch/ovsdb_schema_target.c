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
 * Fuzz harness for the OVSDB schema and related JSON parsing code.
 *
 * Parses the fuzz input as a JSON string and attempts to interpret it as an
 * OVSDB database schema via ovsdb_schema_from_json().  If the schema parses
 * successfully the harness also exercises the condition, mutation, and row
 * JSON parsers against each table in the schema.
 */

#include <config.h>
#include "fuzzer.h"

#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "ovsdb-error.h"
#include "ovsdb/condition.h"
#include "ovsdb/mutation.h"
#include "ovsdb/ovsdb.h"
#include "ovsdb/table.h"
#include "util.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static bool initialized = false;
    if (!initialized) {
        vlog_set_verbosity("off");
        initialized = true;
    }

    /* Require a null-terminated string. */
    if (!size || data[size - 1] != '\0') {
        return 0;
    }

    /* Parse the raw JSON. */
    struct json *json = json_from_string((const char *) data);
    if (!json || json->type == JSON_STRING) {
        json_destroy(json);
        return 0;
    }

    /* Try to interpret the JSON as an OVSDB schema. */
    struct ovsdb_schema *schema = NULL;
    struct ovsdb_error *error = ovsdb_schema_from_json(json, &schema);
    json_destroy(json);

    if (error) {
        ovsdb_error_destroy(error);
        return 0;
    }

    /* Serialize the schema back to JSON and discard. */
    struct json *schema_json = ovsdb_schema_to_json(schema);
    json_destroy(schema_json);

    /* For each table in the schema, try parsing conditions and mutations
     * from trivially-valid JSON arrays (exercises the type-checking paths
     * without needing a second fuzz byte-stream). */
    struct shash_node *node;
    SHASH_FOR_EACH (node, &schema->tables) {
        struct ovsdb_table_schema *ts = node->data;

        /* Empty condition ([]) is always valid. */
        struct json *empty_arr = json_array_create_empty();
        struct ovsdb_condition cond;
        ovsdb_condition_init(&cond);
        error = ovsdb_condition_from_json(ts, empty_arr, NULL, &cond);
        if (!error) {
            struct json *cond_json = ovsdb_condition_to_json(&cond);
            json_destroy(cond_json);
        } else {
            ovsdb_error_destroy(error);
        }
        ovsdb_condition_destroy(&cond);
        json_destroy(empty_arr);

        /* Empty mutation set ([]) is always valid. */
        struct json *empty_mut = json_array_create_empty();
        struct ovsdb_mutation_set ms = OVSDB_MUTATION_SET_INITIALIZER;
        error = ovsdb_mutation_set_from_json(ts, empty_mut, NULL, &ms);
        if (!error) {
            struct json *ms_json = ovsdb_mutation_set_to_json(&ms);
            json_destroy(ms_json);
        } else {
            ovsdb_error_destroy(error);
        }
        ovsdb_mutation_set_destroy(&ms);
        json_destroy(empty_mut);
    }

    ovsdb_schema_destroy(schema);
    return 0;
}

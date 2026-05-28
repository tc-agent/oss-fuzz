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

#include <capnp/test.capnp.h>
#include <capnp/message.h>
#include <capnp/serialize.h>
#include <capnp/dynamic.h>
#include <capnp/any.h>
#include <capnp/schema.h>
#include <kj/exception.h>
#include <kj/io.h>

// Exercises the canonical Cap'n Proto deserialization attack surface: decoding
// an untrusted serialized message and reading every field through the generated
// accessors. The existing capnp-llvm-fuzzer-testcase only ever looks at
// TestAllTypes; this harness additionally drives TestDefaults and the
// nested-list type TestListDefaults, and it re-encodes the decoded TestAllTypes
// message field by field (a message-transformation round trip) so the
// builder-side accessors and the arena allocation paths are exercised with
// fully attacker-controlled values.

namespace c = capnproto_test::capnp::test;

namespace {

volatile uint64_t gSink = 0;

template <typename T>
void sink(T v) { gSink += static_cast<uint64_t>(v); }

// Walk every reader accessor of a TestAllTypes-shaped struct. TestAllTypes and
// TestDefaults share an identical field set, so a single template covers both.
template <typename Reader>
void walkAllTypes(Reader r, int depth) {
  (void)r.getVoidField();
  sink(r.getBoolField());
  sink(r.getInt8Field());
  sink(r.getInt16Field());
  sink(r.getInt32Field());
  sink(r.getInt64Field());
  sink(r.getUInt8Field());
  sink(r.getUInt16Field());
  sink(r.getUInt32Field());
  sink(r.getUInt64Field());
  sink(static_cast<int64_t>(r.getFloat32Field()));
  sink(static_cast<int64_t>(r.getFloat64Field()));
  sink(r.hasTextField());
  sink(r.getTextField().size());
  sink(r.hasDataField());
  sink(r.getDataField().size());
  sink(r.hasStructField());
  sink(static_cast<uint16_t>(r.getEnumField()));

  sink(r.hasVoidList());
  sink(r.getVoidList().size());
  for (auto x : r.getBoolList()) sink(x);
  for (auto x : r.getInt8List()) sink(x);
  for (auto x : r.getInt16List()) sink(x);
  for (auto x : r.getInt32List()) sink(x);
  for (auto x : r.getInt64List()) sink(x);
  for (auto x : r.getUInt8List()) sink(x);
  for (auto x : r.getUInt16List()) sink(x);
  for (auto x : r.getUInt32List()) sink(x);
  for (auto x : r.getUInt64List()) sink(x);
  for (auto x : r.getFloat32List()) sink(static_cast<int64_t>(x));
  for (auto x : r.getFloat64List()) sink(static_cast<int64_t>(x));
  for (auto x : r.getTextList()) sink(x.size());
  for (auto x : r.getDataList()) sink(x.size());
  for (auto x : r.getEnumList()) sink(static_cast<uint16_t>(x));

  if (depth < 4) {
    walkAllTypes(r.getStructField(), depth + 1);
    for (auto s : r.getStructList()) walkAllTypes(s, depth + 1);
  }
}

// Field-by-field copy of a TestAllTypes-shaped struct, driven entirely by the
// decoded (attacker-controlled) values. The struct-list length is capped so a
// hostile list pointer cannot turn the copy into an unbounded allocation; the
// other lists copy at source length, which the bounded ReaderOptions limits.
template <typename Reader, typename Builder>
void copyAllTypes(Reader src, Builder dst, int depth) {
  dst.setVoidField(src.getVoidField());
  dst.setBoolField(src.getBoolField());
  dst.setInt8Field(src.getInt8Field());
  dst.setInt16Field(src.getInt16Field());
  dst.setInt32Field(src.getInt32Field());
  dst.setInt64Field(src.getInt64Field());
  dst.setUInt8Field(src.getUInt8Field());
  dst.setUInt16Field(src.getUInt16Field());
  dst.setUInt32Field(src.getUInt32Field());
  dst.setUInt64Field(src.getUInt64Field());
  dst.setFloat32Field(src.getFloat32Field());
  dst.setFloat64Field(src.getFloat64Field());
  dst.setTextField(src.getTextField());
  dst.setDataField(src.getDataField());
  dst.setEnumField(src.getEnumField());

  auto copyPrimList = [](auto s, auto d) {
    for (unsigned i = 0; i < s.size(); i++) d.set(i, s[i]);
  };
  copyPrimList(src.getBoolList(), dst.initBoolList(src.getBoolList().size()));
  copyPrimList(src.getInt8List(), dst.initInt8List(src.getInt8List().size()));
  copyPrimList(src.getInt16List(), dst.initInt16List(src.getInt16List().size()));
  copyPrimList(src.getInt32List(), dst.initInt32List(src.getInt32List().size()));
  copyPrimList(src.getInt64List(), dst.initInt64List(src.getInt64List().size()));
  copyPrimList(src.getUInt8List(), dst.initUInt8List(src.getUInt8List().size()));
  copyPrimList(src.getUInt16List(), dst.initUInt16List(src.getUInt16List().size()));
  copyPrimList(src.getUInt32List(), dst.initUInt32List(src.getUInt32List().size()));
  copyPrimList(src.getUInt64List(), dst.initUInt64List(src.getUInt64List().size()));
  copyPrimList(src.getFloat32List(), dst.initFloat32List(src.getFloat32List().size()));
  copyPrimList(src.getFloat64List(), dst.initFloat64List(src.getFloat64List().size()));
  copyPrimList(src.getEnumList(), dst.initEnumList(src.getEnumList().size()));

  {
    auto s = src.getTextList();
    auto d = dst.initTextList(s.size());
    for (unsigned i = 0; i < s.size(); i++) d.set(i, s[i]);
  }
  {
    auto s = src.getDataList();
    auto d = dst.initDataList(s.size());
    for (unsigned i = 0; i < s.size(); i++) d.set(i, s[i]);
  }

  if (depth < 2) {
    copyAllTypes(src.getStructField(), dst.initStructField(), depth + 1);
    auto s = src.getStructList();
    unsigned n = kj::min(s.size(), 64u);
    auto d = dst.initStructList(n);
    for (unsigned i = 0; i < n; i++) copyAllTypes(s[i], d[i], depth + 1);
  }
}

// TestListDefaults wraps a TestLists value, which is the codebase's stress
// type for list-of-list and small-struct-list encodings.
void walkLists(c::TestLists::Reader r) {
  for (auto x : r.getList0()) (void)x.getF();
  for (auto x : r.getList1()) sink(x.getF());
  for (auto x : r.getList8()) sink(x.getF());
  for (auto x : r.getList16()) sink(x.getF());
  for (auto x : r.getList32()) sink(x.getF());
  for (auto x : r.getList64()) sink(x.getF());
  for (auto x : r.getListP()) sink(x.getF().size());
  for (auto inner : r.getInt32ListList()) {
    for (auto v : inner) sink(v);
  }
  for (auto inner : r.getTextListList()) {
    for (auto v : inner) sink(v.size());
  }
  for (auto inner : r.getStructListList()) {
    for (auto s : inner) walkAllTypes(s, 3);
  }
}

// Generic recursive walk over the reflection (dynamic) API: every field of an
// untrusted message is reached through DynamicStruct::get, exercising
// dynamic.c++ / schema.c++ rather than the generated static accessors.
void walkDynamic(capnp::DynamicValue::Reader v, int depth) {
  if (depth > 4) return;
  switch (v.getType()) {
    case capnp::DynamicValue::VOID:    break;
    case capnp::DynamicValue::BOOL:    sink(v.as<bool>()); break;
    case capnp::DynamicValue::INT:     sink(v.as<int64_t>()); break;
    case capnp::DynamicValue::UINT:    sink(v.as<uint64_t>()); break;
    case capnp::DynamicValue::FLOAT:   sink(static_cast<int64_t>(v.as<double>())); break;
    case capnp::DynamicValue::TEXT:    sink(v.as<capnp::Text>().size()); break;
    case capnp::DynamicValue::DATA:    sink(v.as<capnp::Data>().size()); break;
    case capnp::DynamicValue::LIST:
      for (auto e : v.as<capnp::DynamicList>()) walkDynamic(e, depth + 1);
      break;
    case capnp::DynamicValue::ENUM: {
      auto e = v.as<capnp::DynamicEnum>();
      sink(e.getRaw());
      (void)e.getEnumerant();
      break;
    }
    case capnp::DynamicValue::STRUCT: {
      auto s = v.as<capnp::DynamicStruct>();
      for (auto field : s.getSchema().getFields()) {
        if (s.has(field)) walkDynamic(s.get(field), depth + 1);
      }
      break;
    }
    case capnp::DynamicValue::CAPABILITY:  break;
    case capnp::DynamicValue::ANY_POINTER: break;
    case capnp::DynamicValue::UNKNOWN:     break;
  }
}

// Treats the message root as a schema-less AnyStruct: walks the raw data and
// pointer sections and runs the canonicalization path in layout.c++.
void walkAny(capnp::AnyStruct::Reader any, int depth) {
  if (depth > 4) return;
  sink(any.getDataSection().size());
  auto ptrs = any.getPointerSection();
  sink(ptrs.size());
  for (auto p : ptrs) {
    if (p.isStruct()) walkAny(p.getAs<capnp::AnyStruct>(), depth + 1);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  kj::ArrayPtr<const uint8_t> array(Data, Size);

  // A hostile message can use overlapping pointers to amplify a tiny input into
  // an enormous logical traversal. Cap the traversal and nesting budgets well
  // below the production defaults so the harness stays fast on adversarial
  // input; the golden seed messages are only a few hundred words.
  capnp::ReaderOptions options;
  options.traversalLimitInWords = 16 * 1024;
  options.nestingLimit = 16;

  // TestAllTypes: read, walk, re-encode field-by-field, then re-read.
  (void)kj::runCatchingExceptions([&]() {
    kj::ArrayInputStream ais(array);
    capnp::InputStreamMessageReader reader(ais, options);
    auto root = reader.getRoot<c::TestAllTypes>();
    walkAllTypes(root, 0);

    capnp::MallocMessageBuilder builder;
    copyAllTypes(root, builder.initRoot<c::TestAllTypes>(), 0);
    kj::Array<capnp::word> flat = capnp::messageToFlatArray(builder);
    capnp::FlatArrayMessageReader roundTrip(flat.asPtr(), options);
    walkAllTypes(roundTrip.getRoot<c::TestAllTypes>(), 0);
  });

  // TestDefaults: identical field set, default-valued.
  (void)kj::runCatchingExceptions([&]() {
    kj::ArrayInputStream ais(array);
    capnp::InputStreamMessageReader reader(ais, options);
    auto root = reader.getRoot<c::TestDefaults>();
    walkAllTypes(root, 0);

    capnp::MallocMessageBuilder builder;
    copyAllTypes(root, builder.initRoot<c::TestDefaults>(), 0);
  });

  // TestListDefaults: nested list / small-struct-list encodings.
  (void)kj::runCatchingExceptions([&]() {
    kj::ArrayInputStream ais(array);
    capnp::InputStreamMessageReader reader(ais, options);
    walkLists(reader.getRoot<c::TestListDefaults>().getLists());
  });

  // Reflection / dynamic API: walk the message generically through the schema.
  (void)kj::runCatchingExceptions([&]() {
    kj::ArrayInputStream ais(array);
    capnp::InputStreamMessageReader reader(ais, options);
    auto dyn = reader.getRoot<capnp::DynamicStruct>(
        capnp::Schema::from<c::TestAllTypes>());
    walkDynamic(dyn, 0);
  });

  // Schema-less view: read the root as AnyStruct, walk its raw sections, and
  // run the canonicalization path.
  (void)kj::runCatchingExceptions([&]() {
    kj::ArrayInputStream ais(array);
    capnp::InputStreamMessageReader reader(ais, options);
    auto any = reader.getRoot<capnp::AnyStruct>();
    walkAny(any, 0);
    kj::Array<capnp::word> canon = any.canonicalize();
    sink(canon.size());
    capnp::FlatArrayMessageReader canonReader(canon.asPtr(), options);
    sink(canonReader.isCanonical());
  });

  return 0;
}

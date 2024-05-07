// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2020 Google Inc.
//

#ifndef JSON_PROTO_CONVERTER_H_
#define JSON_PROTO_CONVERTER_H_

#include <sstream>
#include <string>

#include "LUKS2_plain_JSON.pb.h"

namespace json_proto {

class JsonProtoConverter {
 public:
  std::string Convert(const json_proto::JsonObject&);
  std::string Convert(const json_proto::ArrayValue&);

 private:
  std::stringstream data_;

  void AppendArray(const json_proto::ArrayValue&);
  void AppendNumber(const json_proto::NumberValue&);
  void AppendObject(const json_proto::JsonObject&);
  void AppendValue(const json_proto::JsonValue&);
};

}  // namespace json_proto

#endif  // TESTING_LIBFUZZER_PROTO_JSON_PROTO_CONVERTER_H_

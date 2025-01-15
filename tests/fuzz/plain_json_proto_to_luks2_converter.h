// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup LUKS2 custom mutator fuzz target
 *
 * Copyright (C) 2022-2025 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022-2025 Red Hat, Inc. All rights reserved.
 */

#ifndef LUKS2_PROTO_CONVERTER_H_
#define LUKS2_PROTO_CONVERTER_H_

#include <sstream>
#include <string>
#include <json-c/json.h>

#include "LUKS2_plain_JSON.pb.h"
extern "C" {
#include "crypto_backend/crypto_backend.h"
}

namespace json_proto {

class LUKS2ProtoConverter {
  public:
    ~LUKS2ProtoConverter();
    void create_jobj(const LUKS2_both_headers &headers, uint64_t hdr_size);
    void convert(const LUKS2_both_headers &headers, int fd);
    void create_jobj(const LUKS2_both_headers &headers);
    void emit_luks2_binary_header(const LUKS2_header &header_proto, int fd, uint64_t offset, uint64_t seqid, const std::string &json_text);

    void set_write_headers_only(bool headers_only);

    const uint8_t *get_out_buffer();
    size_t get_out_size();

    static const uint64_t KEYSLOTS_SIZE = 3 * 1024 * 1024;
    static const uint64_t DATA_SIZE = 16 * 1024 * 1024;
  private:
    bool write_headers_only = false;
    struct crypt_hash *hd = NULL;
};

}  // namespace LUKS2_proto

#endif  // LUKS2_PROTO_CONVERTER_H_

/*
 * cryptsetup LUKS2 custom mutator fuzz target
 *
 * Copyright (C) 2022-2023 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022-2023 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

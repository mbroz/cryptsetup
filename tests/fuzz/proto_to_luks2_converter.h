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

#include "LUKS2.pb.h"
extern "C" {
#include "crypto_backend/crypto_backend.h"
}

namespace LUKS2_proto {

class LUKS2ProtoConverter {
  public:
    ~LUKS2ProtoConverter();
    std::string string_uint64_to_string(const string_uint64 &str_u64);
    std::string hash_algorithm_to_string(const hash_algorithm type);
    std::string object_id_to_string(const object_id &oid);

    std::string keyslot_area_type_to_string(const keyslot_area_type type);
    std::string keyslot_kdf_type_to_string(const keyslot_kdf_type type);
    std::string reencrypt_keyslot_mode_to_string(const reencrypt_keyslot_mode mode);
    std::string keyslot_type_to_string(const keyslot_type type);
    std::string reencrypt_keyslot_direction_to_string(const reencrypt_keyslot_direction direction);
    std::string keyslot_af_type_to_string(const keyslot_af_type type);

    std::string config_flag_to_string(config_flag flag);
    std::string config_requirement_to_string(config_requirement requirements);

    std::string segment_type_to_string(segment_type type);
    std::string segment_flag_to_string(segment_flag flag);

    void generate_keyslot(struct json_object *jobj_keyslots, const keyslot_description &keyslot_desc);
    void generate_keyslot_area(struct json_object *jobj_area, const keyslot_area_description &keyslot_area_desc);
    void generate_keyslot_kdf(struct json_object *jobj_kdf, const keyslot_kdf_description &keyslot_kdf_desc);
    void generate_keyslot_af(struct json_object *jobj_af, const keyslot_af_description &keyslot_af_desc);

    void generate_token(struct json_object *jobj_tokens, const token_description &token_desc);

    void generate_digest(struct json_object *jobj_digests, const digest_description &digest_desc);

    void generate_segment_integrity(struct json_object *jobj_integrity, const segment_integrity_description &segment_integrity_desc);
    void generate_segment(struct json_object *jobj_segments, const segment_description &segment_desc);

    void generate_config(const config_description &config_desc, uint64_t json_size, uint64_t keyslots_size);

    void create_jobj(const LUKS2_both_headers &headers, uint64_t hdr_size);
    void emit_luks2_binary_header(uint64_t offset, uint64_t seqid, bool is_primary, uint64_t hdr_size);
    void convert(const LUKS2_both_headers &headers, int fd);
    void create_jobj(const LUKS2_both_headers &headers);
    void emit_luks2_binary_header(const LUKS2_header &header_proto, int fd, uint64_t offset, uint64_t seqid);

    void set_write_headers_only(bool headers_only);

    const uint8_t *get_out_buffer();
    size_t get_out_size();

    static const uint64_t KEYSLOTS_SIZE = 3 * 1024 * 1024;
    static const uint64_t DATA_SIZE = 16 * 1024 * 1024;
  private:
    bool write_headers_only = false;
    struct crypt_hash *hd = NULL;
    struct ::json_object *jobj = NULL;
};

}  // namespace LUKS2_proto

#endif  // LUKS2_PROTO_CONVERTER_H_

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup LUKS2 custom mutator fuzz target
 *
 * Copyright (C) 2022-2025 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022-2025 Red Hat, Inc. All rights reserved.
 */

#include "proto_to_luks2_converter.h"
#include <iostream>

extern "C" {
#include "src/cryptsetup.h"
#include "luks2/luks2.h"
#include <err.h>
}

namespace LUKS2_proto {

std::string LUKS2ProtoConverter::string_uint64_to_string(const string_uint64 &str_u64) {
  std::ostringstream os;

  if (str_u64.negative())
    os << "-";

  if (str_u64.has_uint_num())
    os << str_u64.uint_num();
  else if (str_u64.has_string_num())
    os << str_u64.string_num();

  return os.str();
}

std::string LUKS2ProtoConverter::object_id_to_string(const object_id &oid) {
  std::ostringstream os;

  if (oid.has_int_id()) {
    os << (oid.int_id() % 33) - 16;
  } else if (oid.has_string_id()) {
    os << oid.string_id();
  }

  return os.str();
}

std::string LUKS2ProtoConverter::hash_algorithm_to_string(const hash_algorithm type) {
  switch (type) {
    case HASH_ALG_SHA1:
      return "sha1";
    case HASH_ALG_SHA256:
      return "sha256";
  }
}

std::string LUKS2ProtoConverter::keyslot_area_type_to_string(const keyslot_area_type type) {
  switch (type) {
    case KEYSLOT_AREA_TYPE_RAW:
      return "raw";
    case KEYSLOT_AREA_TYPE_NONE:
      return "none";
    case KEYSLOT_AREA_TYPE_JOURNAL:
      return "journal";
    case KEYSLOT_AREA_TYPE_CHECKSUM:
      return "checksum";
    case KEYSLOT_AREA_TYPE_DATASHIFT:
      return "datashift";
  }
}

void LUKS2ProtoConverter::generate_keyslot_area(struct json_object *jobj_area, const keyslot_area_description &keyslot_area_desc) {
  // mandatory fields
  if (keyslot_area_desc.has_type())
    json_object_object_add(jobj_area, "type", json_object_new_string(keyslot_area_type_to_string(keyslot_area_desc.type()).c_str()));
  if (keyslot_area_desc.has_offset())
    json_object_object_add(jobj_area, "offset", json_object_new_string(string_uint64_to_string(keyslot_area_desc.offset()).c_str()));
  if (keyslot_area_desc.has_size())
    json_object_object_add(jobj_area, "size", json_object_new_string(string_uint64_to_string(keyslot_area_desc.size()).c_str()));

  // raw type fields
  if (keyslot_area_desc.has_encryption())
    json_object_object_add(jobj_area, "encryption", json_object_new_string(keyslot_area_desc.encryption().c_str()));
  if (keyslot_area_desc.has_key_size())
    json_object_object_add(jobj_area, "key_size", json_object_new_int(keyslot_area_desc.key_size()));

  // checksum type fields
  if (keyslot_area_desc.has_hash())
    json_object_object_add(jobj_area, "hash", json_object_new_string(hash_algorithm_to_string(keyslot_area_desc.hash()).c_str()));
  if (keyslot_area_desc.has_sector_size())
    json_object_object_add(jobj_area, "sector_size", json_object_new_int(keyslot_area_desc.sector_size()));

  // datashift type fields
  if (keyslot_area_desc.has_shift_size())
    json_object_object_add(jobj_area, "shift_size", json_object_new_string(string_uint64_to_string(keyslot_area_desc.shift_size()).c_str()));
}

std::string LUKS2ProtoConverter::keyslot_kdf_type_to_string(const keyslot_kdf_type type) {
  switch (type) {
    case KEYSLOT_KDF_TYPE_PBKDF2:
      return "pbkdf2";
    case KEYSLOT_KDF_TYPE_ARGON2I:
      return "argon2i";
    case KEYSLOT_KDF_TYPE_ARGON2ID:
      return "argon2id";
  }
}

void LUKS2ProtoConverter::generate_keyslot_kdf(struct json_object *jobj_kdf, const keyslot_kdf_description &keyslot_kdf_desc) {
  // mandatory fields
  if (keyslot_kdf_desc.has_type())
    json_object_object_add(jobj_kdf, "type", json_object_new_string(keyslot_kdf_type_to_string(keyslot_kdf_desc.type()).c_str()));

  if (keyslot_kdf_desc.has_salt())
    json_object_object_add(jobj_kdf, "salt", json_object_new_string(keyslot_kdf_desc.salt().c_str()));
  else
    json_object_object_add(jobj_kdf, "salt", json_object_new_string("6vz4xK7cjan92rDA5JF8O6Jk2HouV0O8DMB6GlztVk="));

  // pbkdf2 type
  if (keyslot_kdf_desc.has_hash())
    json_object_object_add(jobj_kdf, "hash", json_object_new_string(hash_algorithm_to_string(keyslot_kdf_desc.hash()).c_str()));
  if (keyslot_kdf_desc.has_iterations())
    json_object_object_add(jobj_kdf, "iterations", json_object_new_int(keyslot_kdf_desc.iterations()));

  // argon2i and argon2id types
  if (keyslot_kdf_desc.has_time())
    json_object_object_add(jobj_kdf, "time", json_object_new_int(keyslot_kdf_desc.time()));
  if (keyslot_kdf_desc.has_memory())
    json_object_object_add(jobj_kdf, "memory", json_object_new_int(keyslot_kdf_desc.memory()));
  if (keyslot_kdf_desc.has_cpus())
    json_object_object_add(jobj_kdf, "cpus", json_object_new_int(keyslot_kdf_desc.cpus()));
}

std::string LUKS2ProtoConverter::keyslot_af_type_to_string(const keyslot_af_type type) {
  switch (type) {
    case KEYSLOT_AF_TYPE_LUKS1:
      return "luks1";
  }
}

void LUKS2ProtoConverter::generate_keyslot_af(struct json_object *jobj_af, const keyslot_af_description &keyslot_af_desc) {
  if (keyslot_af_desc.has_type())
    json_object_object_add(jobj_af, "type", json_object_new_string(keyslot_af_type_to_string(keyslot_af_desc.type()).c_str()));
  if (keyslot_af_desc.has_stripes())
    json_object_object_add(jobj_af, "stripes", json_object_new_int(keyslot_af_desc.stripes()));
  if (keyslot_af_desc.has_hash())
    json_object_object_add(jobj_af, "hash", json_object_new_string(hash_algorithm_to_string(keyslot_af_desc.hash()).c_str()));
}

std::string LUKS2ProtoConverter::keyslot_type_to_string(const keyslot_type type) {
  switch (type) {
    case KEYSLOT_TYPE_LUKS2:
      return "luks2";
    case KEYSLOT_TYPE_REENCRYPT:
      return "reencrypt";
    case KEYSLOT_TYPE_PLACEHOLDER:
      return "placeholder";
  }
}

std::string LUKS2ProtoConverter::reencrypt_keyslot_mode_to_string(const reencrypt_keyslot_mode mode) {
  switch (mode) {
    case MODE_REENCRYPT:
      return "reencrypt";
    case MODE_ENCRYPT:
      return "encrypt";
    case MODE_DECRYPT:
      return "decrypt";
  }
}

std::string LUKS2ProtoConverter::reencrypt_keyslot_direction_to_string(const reencrypt_keyslot_direction direction) {
  switch (direction) {
    case DIRECTION_FORWARD:
      return "forward";
    case DIRECTION_BACKWARD:
      return "backward";
  }
}

void LUKS2ProtoConverter::generate_keyslot(struct json_object *jobj_keyslots, const keyslot_description &keyslot_desc) {
  struct json_object *jobj_keyslot, *jobj_area, *jobj_kdf, *jobj_af;

  jobj_keyslot = json_object_new_object();
  if (keyslot_desc.has_type())
    json_object_object_add(jobj_keyslot, "type", json_object_new_string(keyslot_type_to_string(keyslot_desc.type()).c_str()));
  if (keyslot_desc.has_key_size())
    json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(keyslot_desc.key_size()));
  if (keyslot_desc.has_priority())
    json_object_object_add(jobj_keyslot, "priority", json_object_new_int(keyslot_desc.priority()));
  if (keyslot_desc.has_mode())
    json_object_object_add(jobj_keyslot, "mode", json_object_new_int(keyslot_desc.mode()));
  if (keyslot_desc.has_direction())
    json_object_object_add(jobj_keyslot, "direction", json_object_new_int(keyslot_desc.direction()));

  /* Area object */
  if (keyslot_desc.has_area()) {
    jobj_area = json_object_new_object();
    generate_keyslot_area(jobj_area, keyslot_desc.area());
    json_object_object_add(jobj_keyslot, "area", jobj_area);
  }

  /* KDF object */
  if (keyslot_desc.has_kdf()) {
    jobj_kdf = json_object_new_object();
    generate_keyslot_kdf(jobj_kdf, keyslot_desc.kdf());
    json_object_object_add(jobj_keyslot, "kdf", jobj_kdf);
  }

  /* AF object */
  if (keyslot_desc.has_af()) {
    jobj_af = json_object_new_object();
    generate_keyslot_af(jobj_af, keyslot_desc.af());
    json_object_object_add(jobj_keyslot, "af", jobj_af);
  }

  json_object_object_add(jobj_keyslots, object_id_to_string(keyslot_desc.oid()).c_str(), jobj_keyslot);
}

void LUKS2ProtoConverter::generate_token(struct json_object *jobj_tokens, const token_description &token_desc) {
  struct json_object *jobj_token, *jobj_keyslots;
  jobj_token = json_object_new_object();

  if (token_desc.has_type())
    json_object_object_add(jobj_token, "type", json_object_new_string(token_desc.type().c_str()));

  if (token_desc.has_key_description())
    json_object_object_add(jobj_token, "key_description", json_object_new_string(token_desc.key_description().c_str()));

  if (!token_desc.keyslots().empty()) {
    jobj_keyslots = json_object_new_array();

    for (const object_id& oid : token_desc.keyslots()) {
        json_object_array_add(jobj_keyslots,
            json_object_new_string(object_id_to_string(oid).c_str()));
    }

    /* Replace or add new keyslots array */
    json_object_object_add(jobj_token, "keyslots", jobj_keyslots);
  }

  json_object_object_add(jobj_tokens, object_id_to_string(token_desc.oid()).c_str(), jobj_token);
}

void LUKS2ProtoConverter::generate_digest(struct json_object *jobj_digests, const digest_description &digest_desc) {
  struct json_object *jobj_digest, *jobj_keyslots, *jobj_segments;

  jobj_digest = json_object_new_object();

  if (digest_desc.has_type())
    json_object_object_add(jobj_digest, "type", json_object_new_string(keyslot_kdf_type_to_string(digest_desc.type()).c_str()));

  if (!digest_desc.keyslots().empty()) {
    jobj_keyslots = json_object_new_array();

    for (const object_id& oid : digest_desc.keyslots()) {
        json_object_array_add(jobj_keyslots,
            json_object_new_string(object_id_to_string(oid).c_str()));
    }

    /* Replace or add new keyslots array */
    json_object_object_add(jobj_digest, "keyslots", jobj_keyslots);
  }

  if (!digest_desc.segments().empty()) {
    jobj_segments = json_object_new_array();

    for (const object_id& oid : digest_desc.segments()) {
        json_object_array_add(jobj_segments,
            json_object_new_string(object_id_to_string(oid).c_str()));
    }

    /* Replace or add new segments array */
    json_object_object_add(jobj_digest, "segments", jobj_segments);
  }

  if (digest_desc.has_salt())
    json_object_object_add(jobj_digest, "salt", json_object_new_string(digest_desc.salt().c_str()));
  if (digest_desc.has_digest())
    json_object_object_add(jobj_digest, "digest", json_object_new_string(digest_desc.digest().c_str()));
  if (digest_desc.has_hash())
    json_object_object_add(jobj_digest, "hash", json_object_new_string(hash_algorithm_to_string(digest_desc.hash()).c_str()));
  if (digest_desc.has_iterations())
    json_object_object_add(jobj_digest, "iterations", json_object_new_int(digest_desc.iterations()));

  json_object_object_add(jobj_digests, object_id_to_string(digest_desc.oid()).c_str(), jobj_digest);
}

std::string LUKS2ProtoConverter::segment_type_to_string(segment_type type) {
  switch (type) {
    case SEGMENT_TYPE_LINEAR:
      return "linear";
    case SEGMENT_TYPE_CRYPT:
      return "crypt";
  }
}

std::string LUKS2ProtoConverter::segment_flag_to_string(segment_flag flag) {
  switch (flag) {
    case IN_REENCRYPTION:
      return "in-reencryption";
    case BACKUP_FINAL:
      return "backup-final";
    case BACKUP_PREVIOUS:
      return "backup-previous";
    case BACKUP_MOVED_SEGMENT:
      return "backup-moved-segment";
  }
}

void LUKS2ProtoConverter::generate_segment_integrity(struct json_object *jobj_integrity, const segment_integrity_description &segment_integrity_desc) {
  if (segment_integrity_desc.has_type())
    json_object_object_add(jobj_integrity, "type", json_object_new_string(segment_integrity_desc.type().c_str()));
  if (segment_integrity_desc.has_journal_encryption())
    json_object_object_add(jobj_integrity, "journal_encryption", json_object_new_string(segment_integrity_desc.journal_encryption().c_str()));
  if (segment_integrity_desc.has_journal_integrity())
    json_object_object_add(jobj_integrity, "journal_integrity", json_object_new_string(segment_integrity_desc.journal_integrity().c_str()));
}

void LUKS2ProtoConverter::generate_segment(struct json_object *jobj_segments, const segment_description &segment_desc) {
  json_object *jobj_flags, *jobj_integrity;
  json_object *jobj_segment = json_object_new_object();

  if (segment_desc.has_type())
    json_object_object_add(jobj_segment, "type", json_object_new_string(segment_type_to_string(segment_desc.type()).c_str()));

  if (segment_desc.has_offset())
    json_object_object_add(jobj_segment, "offset", json_object_new_string(string_uint64_to_string(segment_desc.offset()).c_str()));
  if (segment_desc.has_size())
    json_object_object_add(jobj_segment, "size", json_object_new_string(string_uint64_to_string(segment_desc.size()).c_str()));

  if (!segment_desc.flags().empty()) {
    jobj_flags = json_object_new_array();

    for (const int flag : segment_desc.flags()) {
        json_object_array_add(jobj_flags,
            json_object_new_string(segment_flag_to_string(segment_flag(flag)).c_str()));
    }

    /* Replace or add new flags array */
    json_object_object_add(jobj_segment, "flags", jobj_flags);
  }

  if (segment_desc.has_iv_tweak())
    json_object_object_add(jobj_segment, "iv_tweak", json_object_new_string(string_uint64_to_string(segment_desc.iv_tweak()).c_str()));
  if (segment_desc.has_encryption())
    json_object_object_add(jobj_segment, "encryption", json_object_new_string(segment_desc.encryption().c_str()));
  if (segment_desc.has_sector_size())
    json_object_object_add(jobj_segment, "sector_size", json_object_new_int(segment_desc.sector_size()));

  if (segment_desc.has_integrity()) {
    jobj_integrity = json_object_new_object();
    generate_segment_integrity(jobj_integrity, segment_desc.integrity());
    json_object_object_add(jobj_segment, "integrity", jobj_integrity);
  }

  json_object_object_add(jobj_segments, object_id_to_string(segment_desc.oid()).c_str(), jobj_segment);
}

void LUKS2ProtoConverter::create_jobj(const LUKS2_both_headers &headers) {
  json_object *jobj_keyslots = NULL;
  json_object *jobj_digests = NULL;
  json_object *jobj_segments = NULL;
  json_object *jobj_tokens = NULL;

  const json_area_description &json_desc = headers.json_area();

  jobj = json_object_new_object();
  if (!jobj)
    return;

  jobj_keyslots = json_object_new_object();
  for (const keyslot_description &keyslot_desc : json_desc.keyslots()) {
    generate_keyslot(jobj_keyslots, keyslot_desc);
  }
  json_object_object_add(jobj, "keyslots", jobj_keyslots);

  jobj_digests = json_object_new_object();
  for (const digest_description &digest_desc : json_desc.digests()) {
    generate_digest(jobj_digests, digest_desc);
  }
  json_object_object_add(jobj, "digests", jobj_digests);

  jobj_segments = json_object_new_object();
  for (const segment_description &segment_desc : json_desc.segments()) {
    generate_segment(jobj_segments, segment_desc);
  }
  json_object_object_add(jobj, "segments", jobj_segments);

  jobj_tokens = json_object_new_object();
  for (const token_description &token_desc : json_desc.tokens()) {
    generate_token(jobj_tokens, token_desc);
  }
  json_object_object_add(jobj, "tokens", jobj_tokens);

  if (json_desc.has_config()) {
    uint64_t hdr_size = json_desc.config().use_primary_hdr_size() ? headers.primary_header().hdr_size() : headers.secondary_header().hdr_size();
    generate_config(json_desc.config(), hdr_size - LUKS2_HDR_BIN_LEN, KEYSLOTS_SIZE);
  }
}

void LUKS2ProtoConverter::emit_luks2_binary_header(const LUKS2_header &header_proto, int fd, uint64_t offset, uint64_t seqid) {
  struct luks2_hdr_disk hdr = {};
  int r;

  if (hd)
    crypt_hash_destroy(hd);
  if (crypt_hash_init(&hd, "sha256"))
    err(EXIT_FAILURE, "crypt_hash_init failed");


  r = lseek(fd, offset, SEEK_SET);
  if (r == -1)
    err(EXIT_FAILURE, "lseek failed");

  switch (header_proto.magic()) {
    case INVALID:
      memset(&hdr.magic, 0, LUKS2_MAGIC_L);
      break;
    case FIRST:
      memcpy(&hdr.magic, LUKS2_MAGIC_1ST, LUKS2_MAGIC_L);
      break;
    case SECOND:
      memcpy(&hdr.magic, LUKS2_MAGIC_2ND, LUKS2_MAGIC_L);
      break;
  }
  hdr.version     = cpu_to_be16(header_proto.version());
  hdr.hdr_size    = cpu_to_be64(header_proto.hdr_size());
  hdr.seqid       = cpu_to_be64(seqid);
  strncpy(hdr.checksum_alg, "sha256", LUKS2_CHECKSUM_ALG_L);
  hdr.checksum_alg[LUKS2_CHECKSUM_ALG_L - 1] = '\0';
  strncpy(hdr.uuid, "af7f64ea-3233-4581-946b-6187d812841e", LUKS2_UUID_L);
  memset(hdr.salt, 1, LUKS2_SALT_L);


  if (header_proto.has_selected_offset())
    hdr.hdr_offset  = cpu_to_be64(header_proto.selected_offset());
  else
    hdr.hdr_offset  = cpu_to_be64(offset);

  if (write_buffer(fd, &hdr, LUKS2_HDR_BIN_LEN) != LUKS2_HDR_BIN_LEN)
    err(EXIT_FAILURE, "write_buffer failed");
  if (crypt_hash_write(hd, (char*)&hdr, LUKS2_HDR_BIN_LEN))
    err(EXIT_FAILURE, "crypt_hash_write failed");

  size_t hdr_json_area_len = header_proto.hdr_size() - LUKS2_HDR_BIN_LEN;
  size_t json_text_len;
  const char *json_text;
  uint8_t csum[LUKS2_CHECKSUM_L];

  if (jobj) {
    json_text = json_object_to_json_string_ext((struct json_object *)jobj, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!json_text || !*json_text)
      err(EXIT_FAILURE, "json_object_to_json_string_ext failed");

    json_text_len = strlen(json_text);

    size_t write_size = json_text_len > hdr_json_area_len - 1 ? hdr_json_area_len - 1 : json_text_len;
    if (write_buffer(fd, json_text, write_size) != (ssize_t)write_size)
      err(EXIT_FAILURE, "write_buffer failed");
    if (crypt_hash_write(hd, json_text, write_size))
      err(EXIT_FAILURE, "crypt_hash_write failed");

    for (size_t i = 0; i < (hdr_json_area_len - write_size); i++) {
      if (crypt_hash_write(hd, "\0", 1))
        err(EXIT_FAILURE, "crypt_hash_write failed");
    }
  }

  if (header_proto.use_correct_checksum()) {
    if (lseek(fd, offset + offsetof(luks2_hdr_disk, csum), SEEK_SET) == -1)
      err(EXIT_FAILURE, "lseek failed");

    int hash_size = crypt_hash_size("sha256");
    if (hash_size <= 0)
      err(EXIT_FAILURE, "crypt_hash_size failed");

    if (crypt_hash_final(hd, (char*)csum, (size_t)hash_size))
      err(EXIT_FAILURE, "crypt_hash_final failed");
    if (write_buffer(fd, csum, hash_size) != hash_size)
      err(EXIT_FAILURE, "write_buffer failed");
  }
}

void LUKS2ProtoConverter::set_write_headers_only(bool headers_only) {
  write_headers_only = headers_only;
}

void LUKS2ProtoConverter::convert(const LUKS2_both_headers &headers, int fd) {
  uint64_t primary_seqid, secondary_seqid;
  int result;

  size_t out_size = headers.primary_header().hdr_size() + headers.secondary_header().hdr_size();

  if (!write_headers_only)
    out_size += KEYSLOTS_SIZE + DATA_SIZE;

  result = ftruncate(fd, out_size);
  if (result == -1)
    err(EXIT_FAILURE, "truncate failed");

  result = lseek(fd, 0, SEEK_SET);
  if (result == -1)
    err(EXIT_FAILURE, "lseek failed");

  switch (headers.seqid()) {
    case EQUAL:
      primary_seqid = 1;
      secondary_seqid = 1;
      break;
    case PRIMARY_GREATER:
      primary_seqid = 2;
      secondary_seqid = 1;
      break;
    case SECONDARY_GREATER:
      primary_seqid = 1;
      secondary_seqid = 2;
      break;
  }

  create_jobj(headers);
  emit_luks2_binary_header(headers.primary_header(), fd, 0, primary_seqid);
  emit_luks2_binary_header(headers.secondary_header(), fd, headers.primary_header().hdr_size(), secondary_seqid);
}

std::string LUKS2ProtoConverter::config_flag_to_string(config_flag flag) {
  switch (flag) {
    case CONFIG_FLAG_ALLOW_DISCARDS:
      return "allow-discards";
    case CONFIG_FLAG_SAME_CPU_CRYPT:
      return "same-cpu-crypt";
    case CONFIG_FLAG_SUBMIT_FROM_CRYPT_CPUS:
      return "submit-from-crypt-cpus";
    case CONFIG_FLAG_NO_JOURNAL:
      return "no-journal";
    case CONFIG_FLAG_NO_READ_WORKQUEUE:
      return "no-read-workqueue";
    case CONFIG_FLAG_NO_WRITE_WORKQUEUE:
      return "no-write-workqueue";
  }
}

std::string LUKS2ProtoConverter::config_requirement_to_string(config_requirement requirement) {
  switch (requirement) {
    case CONFIG_REQUIREMENT_OFFLINE_REENCRYPT:
      return "offline-reencrypt";
    case CONFIG_REQUIREMENT_ONLINE_REENCRYPT_V2:
      return "online-reencrypt-v2";
  }
}

void LUKS2ProtoConverter::generate_config(const config_description &config_desc, uint64_t json_size, uint64_t keyslots_size) {
  json_object *jobj_config, *jobj_flags, *jobj_requirements, *jobj_mandatory;
  jobj_config = json_object_new_object();

  json_object_object_add(jobj_config, "json_size", json_object_new_string(std::to_string(json_size).c_str()));
  json_object_object_add(jobj_config, "keyslots_size", json_object_new_string(std::to_string(keyslots_size).c_str()));

  if (!config_desc.config_flags().empty()) {
    jobj_flags = json_object_new_array();

    for (const int flag : config_desc.config_flags()) {
        json_object_array_add(jobj_flags,
            json_object_new_string(config_flag_to_string(config_flag(flag)).c_str()));
    }

    /* Replace or add new flags array */
    json_object_object_add(jobj_config, "flags", jobj_flags);
  }

  if (!config_desc.requirements().empty()) {
    jobj_requirements = json_object_new_object();
    jobj_mandatory = json_object_new_array();

    for (const int requirement : config_desc.requirements()) {
        json_object_array_add(jobj_mandatory,
            json_object_new_string(config_requirement_to_string(config_requirement(requirement)).c_str()));
    }

    /* Replace or add new requirements array */
    json_object_object_add(jobj_requirements, "mandatory", jobj_mandatory);
    json_object_object_add(jobj_config, "requirements", jobj_requirements);
  }

  json_object_object_add(jobj, "config", jobj_config);
}

LUKS2ProtoConverter::~LUKS2ProtoConverter() {
  json_object_put(jobj);
  if (hd)
    crypt_hash_destroy(hd);
}
}  // namespace LUKS2_proto

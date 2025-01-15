// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup LUKS2 custom mutator fuzz target
 *
 * Copyright (C) 2022-2025 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022-2025 Red Hat, Inc. All rights reserved.
 */

#include "plain_json_proto_to_luks2_converter.h"
#include "json_proto_converter.h"

extern "C" {
#include "src/cryptsetup.h"
#include "luks2/luks2.h"
#include <err.h>
}

namespace json_proto {

void LUKS2ProtoConverter::emit_luks2_binary_header(const LUKS2_header &header_proto, int fd, uint64_t offset, uint64_t seqid, const std::string &json_text) {
  struct luks2_hdr_disk hdr = {};
  size_t hdr_json_area_len, write_size;
  uint8_t csum[LUKS2_CHECKSUM_L];
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

  if (header_proto.hdr_size() <= LUKS2_HDR_BIN_LEN ||
      header_proto.hdr_size() > LUKS2_DEFAULT_HDR_SIZE)
      hdr_json_area_len = LUKS2_DEFAULT_HDR_SIZE - LUKS2_HDR_BIN_LEN;
  else
      hdr_json_area_len = header_proto.hdr_size() - LUKS2_HDR_BIN_LEN;

  write_size = json_text.length() > hdr_json_area_len - 1 ? hdr_json_area_len - 1 : json_text.length();
  if (write_buffer(fd, json_text.c_str(), write_size) != (ssize_t)write_size)
    err(EXIT_FAILURE, "write_buffer failed");
  if (crypt_hash_write(hd, json_text.c_str(), write_size))
    err(EXIT_FAILURE, "crypt_hash_write failed");

  for (size_t i = 0; i < (hdr_json_area_len - write_size); i++) {
    if (crypt_hash_write(hd, "\0", 1))
      err(EXIT_FAILURE, "crypt_hash_write failed");
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

  if (out_size < 4096 || out_size > 2 * LUKS2_DEFAULT_HDR_SIZE)
    out_size = LUKS2_DEFAULT_HDR_SIZE;

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

  JsonProtoConverter converter;
  std::string json_text = converter.Convert(headers.json_area());

  emit_luks2_binary_header(headers.primary_header(), fd, 0, primary_seqid, json_text);
  emit_luks2_binary_header(headers.secondary_header(), fd, headers.primary_header().hdr_size(), secondary_seqid, json_text);
}

LUKS2ProtoConverter::~LUKS2ProtoConverter() {
  if (hd)
    crypt_hash_destroy(hd);
}
}  // namespace LUKS2_proto

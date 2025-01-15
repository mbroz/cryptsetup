// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup LUKS2 custom mutator fuzz target
 *
 * Copyright (C) 2022-2025 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022-2025 Red Hat, Inc. All rights reserved.
 */

#include "LUKS2_plain_JSON.pb.h"
#include "plain_json_proto_to_luks2_converter.h"
#include "libfuzzer/libfuzzer_macro.h"
#include "FuzzerInterface.h"

extern "C" {
#include <libcryptsetup.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
}

DEFINE_PROTO_FUZZER(const json_proto::LUKS2_both_headers &headers) {
  struct crypt_device *cd = NULL;
  char name[] = "/tmp/test-proto-fuzz.XXXXXX";
  int fd = mkostemp(name, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC);

  if (fd < 0)
    err(EXIT_FAILURE, "mkostemp() failed");

  json_proto::LUKS2ProtoConverter converter;
  converter.convert(headers, fd);

  if (crypt_init(&cd, name) == 0)
    (void)crypt_load(cd, CRYPT_LUKS2, NULL);
  crypt_free(cd);

  close(fd);
  unlink(name);
}

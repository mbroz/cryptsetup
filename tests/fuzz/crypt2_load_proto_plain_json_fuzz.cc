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

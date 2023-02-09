/*
 * cryptsetup LUKS2 protobuf to image converter
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

#include <iostream>
#include <string>

#include <fcntl.h>
#include <unistd.h>

#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include "plain_json_proto_to_luks2_converter.h"

using namespace json_proto;

int main(int argc, char *argv[]) {
  LUKS2_both_headers headers;
  LUKS2ProtoConverter converter;
  int fd;

  std::string out_img_name;

  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <LUKS2 proto>\n";
    return EXIT_FAILURE;
  }

  fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    std::cerr << "Failed to open " << argv[1] << std::endl;
    return EXIT_FAILURE;
  }

  google::protobuf::io::FileInputStream fileInput(fd);

  if (!google::protobuf::TextFormat::Parse(&fileInput, &headers)) {
    std::cerr << "Failed to parse protobuf " << argv[1] << std::endl;
    close(fd);
    return EXIT_FAILURE;
  }
  close(fd);

  out_img_name = argv[1];
  out_img_name += ".img";

  fd = open(out_img_name.c_str(), O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_TRUNC, 0644);
  if (fd < 0) {
    std::cerr << "Failed to open output file " << out_img_name << std::endl;
    return EXIT_FAILURE;
  }
  converter.set_write_headers_only(false);
  converter.convert(headers, fd);

  close(fd);
  return EXIT_SUCCESS;
}

#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate LUKS2 header with non compact (valid!)
# json and additional token with id 0 with json
# format aligned to 4K boundary.
#
# The image is tested for correct LUKS2 write optimization
# where non compact json trailing bytes must not remain in LUKS2 json
# area after write of shorter (e.g. compact) json.

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# add empty token
	json_str=$(jq -c '.tokens."0" = {"type":"a", "keyslots":[]}' $TMPDIR/json0)
	json_len_orig=${#json_str}
	test $json_len_orig -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	# align to 4k and full 4K of whitespace if already aligned
	json_fill_len=$((4096-(json_len_orig%4096)))
	fill=$(repeat_str " " $json_fill_len)
	json_str_new=$(echo -e $json_str | sed -e "s/\(\"type\":\)\(\"luks2\"\)/\1""$fill""\2/")
	json_len_new=${#json_str_new}

	test $((json_len_new%4096)) -eq 0 || exit 2
	test $json_len_new -lt $((LUKS2_JSON_SIZE*512)) || exit 2
	test $json_len_new -gt $json_len_orig || exit 2

	printf '%s' "$json_str_new" | _dd of=$TMPDIR/json0 bs=4K conv=notrunc
	printf '%s' "$json_str_new" | _dd of=$TMPDIR/json1 bs=4K conv=notrunc

	lib_mangle_json_hdr0
	lib_mangle_json_hdr1
}

check()
{
	lib_hdr0_checksum || exit 2
	lib_hdr1_checksum || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0

	read -r json_str_res < $TMPDIR/json_res0
	test $((${#json_str_res}%4096)) -eq 0 || exit 2
	test ${#json_str_res} -gt $json_len_orig || exit 2
}

lib_prepare $@
generate
check
lib_cleanup

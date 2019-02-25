/*
 * LUKS - Linux Unified Key Setup v2, internal segment handling
 *
 * Copyright (C) 2018-2019, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2019, Ondrej Kozina
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

#include "luks2_internal.h"

json_object *json_get_segments_jobj(json_object *hdr_jobj)
{
	json_object *jobj_segments;

	if (!hdr_jobj || !json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments))
		return NULL;

	return jobj_segments;
}

uint64_t json_segment_get_offset(json_object *jobj_segment, unsigned blockwise)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "offset", &jobj))
		return 0;

	return blockwise ? json_object_get_uint64(jobj) >> SECTOR_SHIFT : json_object_get_uint64(jobj);
}

const char *json_segment_type(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "type", &jobj))
		return NULL;

	return json_object_get_string(jobj);
}

uint64_t json_segment_get_iv_offset(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "iv_tweak", &jobj))
		return 0;

	return json_object_get_uint64(jobj);
}

uint64_t json_segment_get_size(json_object *jobj_segment, unsigned blockwise)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "size", &jobj))
		return 0;

	return blockwise ? json_object_get_uint64(jobj) >> SECTOR_SHIFT : json_object_get_uint64(jobj);
}

const char *json_segment_get_cipher(json_object *jobj_segment)
{
	json_object *jobj;

	/* FIXME: Pseudo "null" cipher should be handled elsewhere */
	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "encryption", &jobj))
		return "null";

	return json_object_get_string(jobj);
}

int json_segment_get_sector_size(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
            !json_object_object_get_ex(jobj_segment, "sector_size", &jobj))
		return -1;

	return json_object_get_int(jobj);
}

json_object *json_segment_get_flags(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment || !(json_object_object_get_ex(jobj_segment, "flags", &jobj)))
		return NULL;
	return jobj;
}

json_object *json_segments_get_segment(json_object *jobj_segments, int segment)
{
	json_object *jobj;
	char segment_name[16];

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(jobj_segments, segment_name, &jobj))
		return NULL;

	return jobj;
}

int json_segments_count(json_object *jobj_segments)
{
	if (!jobj_segments)
		return -EINVAL;

	return json_object_object_length(jobj_segments);
}

static void _get_segment_or_id_by_flag(json_object *jobj_segments, const char *flag, unsigned id, void *retval)
{
	json_object *jobj_flags, **jobj_ret = (json_object **)retval;
	int *ret = (int *)retval;

	if (!flag)
		return;

	json_object_object_foreach(jobj_segments, key, value) {
		if (!json_object_object_get_ex(value, "flags", &jobj_flags))
			continue;
		if (LUKS2_array_jobj(jobj_flags, flag)) {
			if (id)
				*ret = atoi(key);
			else
				*jobj_ret = value;
			return;
		}
	}
}

json_object *json_segments_get_segment_by_flag(json_object *jobj_segments, const char *flag)
{
	json_object *jobj_segment = NULL;

	if (jobj_segments)
		_get_segment_or_id_by_flag(jobj_segments, flag, 0, &jobj_segment);

	return jobj_segment;
}

void json_segment_remove_flag(json_object *jobj_segment, const char *flag)
{
	json_object *jobj_flags, *jobj_flags_new;

	if (!jobj_segment)
		return;

	jobj_flags = json_segment_get_flags(jobj_segment);
	if (!jobj_flags)
		return;

	jobj_flags_new = LUKS2_array_remove(jobj_flags, flag);
	if (!jobj_flags_new)
		return;

	if (json_object_array_length(jobj_flags_new) <= 0) {
		json_object_put(jobj_flags_new);
		json_object_object_del(jobj_segment, "flags");
	} else
		json_object_object_add(jobj_segment, "flags", jobj_flags_new);
}

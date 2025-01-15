// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Command line arguments parsing helpers
 *
 * Copyright (C) 2020-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020-2025 Ondrej Kozina
 */

#include "cryptsetup.h"

void tools_parse_arg_value(poptContext popt_context, crypt_arg_type_info type, struct tools_arg *arg, const char *popt_arg, int popt_val, bool(*needs_size_conv_fn)(unsigned arg_id))
{
	char *end, msg[128];
	long long int ll;
	long long unsigned int ull;

	errno = 0;

	switch (type) {
	case CRYPT_ARG_BOOL:
		break;
	case CRYPT_ARG_STRING:
		if (arg->set)
			free(arg->u.str_value);
		arg->u.str_value = poptGetOptArg(popt_context);
		break;
	case CRYPT_ARG_INT32:
		ll = strtoll(popt_arg, &end, 10);
		if (*end || !*popt_arg || ll > INT32_MAX || ll < INT32_MIN || errno == ERANGE)
			usage(popt_context, EXIT_FAILURE, poptStrerror(POPT_ERROR_BADNUMBER),
			      poptGetInvocationName(popt_context));
		arg->u.i32_value = (int32_t)ll;
		break;
	case CRYPT_ARG_UINT32:
		ull = strtoull(popt_arg, &end, 10);
		if (*end || !*popt_arg || ull > UINT32_MAX || errno == ERANGE)
			usage(popt_context, EXIT_FAILURE, poptStrerror(POPT_ERROR_BADNUMBER),
			      poptGetInvocationName(popt_context));
		arg->u.u32_value = (uint32_t)ull;
		break;
	case CRYPT_ARG_INT64:
		ll = strtoll(popt_arg, &end, 10);
		if (*end || !*popt_arg || errno == ERANGE)
			usage(popt_context, EXIT_FAILURE, poptStrerror(POPT_ERROR_BADNUMBER),
			      poptGetInvocationName(popt_context));
		arg->u.i64_value = ll;
		break;
	case CRYPT_ARG_UINT64:
		/* special size strings with units converted to integers */
		if (needs_size_conv_fn && needs_size_conv_fn(popt_val)) {
			if (tools_string_to_size(popt_arg, &arg->u.u64_value)) {
				if (snprintf(msg, sizeof(msg), _("Invalid size specification in parameter --%s."), arg->name) < 0)
					msg[0] = '\0';
				usage(popt_context, EXIT_FAILURE, msg,
				      poptGetInvocationName(popt_context));
			}
		} else {
			ull = strtoull(popt_arg, &end, 10);
			if (*end || !*popt_arg || errno == ERANGE)
				usage(popt_context, EXIT_FAILURE, poptStrerror(POPT_ERROR_BADNUMBER),
				      poptGetInvocationName(popt_context));
			arg->u.u64_value = ull;
		}
		break;
	case CRYPT_ARG_ALIAS:
		tools_parse_arg_value(popt_context, arg->u.o.ptr->type, arg->u.o.ptr, popt_arg, arg->u.o.id, needs_size_conv_fn);
		break;
	default:
		/* this signals internal tools coding mistake */
		abort();
	}

	arg->set = true;
}

void tools_args_free(struct tools_arg *args, size_t args_size)
{
	size_t i;

	for (i = 0; i < args_size; i++) {
		if (args[i].set && args[i].type == CRYPT_ARG_STRING)
			free(args[i].u.str_value);
		args[i].set = false;
	}
}

static bool action_allowed(const char *action, const char * const* list, size_t list_size)
{
	size_t i;

	if (!list[0])
		return true;

	for (i = 0; i < list_size && list[i]; i++) {
		if (!strcmp(action, list[i]))
			return true;
	}

	return false;
}

void tools_check_args(const char *action, const struct tools_arg *args, size_t args_size, poptContext popt_context)
{
	size_t i;
	char msg[256];

	for (i = 1; i < args_size; i++) {
		if (args[i].set) {
			if (action_allowed(action, args[i].actions_array, MAX_ACTIONS)) {
				continue;
			} else {
				if (snprintf(msg, sizeof(msg), _("Option --%s is not allowed with %s action."), args[i].name, action) < 0)
					msg[0] = '\0';
				usage(popt_context, EXIT_FAILURE, msg, poptGetInvocationName(popt_context));
			}
		}
	}
}

/*
 * Python bindings to libcryptsetup
 *
 * Copyright (C) 2009-2014, Red Hat, Inc. All rights reserved.
 * Written by Martin Sivak
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <Python.h>
#include <structmember.h>
#include <errno.h>

#include "libcryptsetup.h"

/* Python API use char* where const char* should be used... */
#define CONST_CAST(x) (x)(uintptr_t)

#if PY_MAJOR_VERSION < 3
  #define MOD_ERROR_VAL
  #define MOD_SUCCESS_VAL(val)
  #define MOD_INIT(name) void init##name(void)
  #define MOD_DEF(ob, name, doc, methods) \
          ob = Py_InitModule3(name, methods, doc);
#else
  #define PyInt_AsLong PyLong_AsLong
  #define PyInt_Check PyLong_Check
  #define MOD_ERROR_VAL NULL
  #define MOD_SUCCESS_VAL(val) val
  #define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
  #define MOD_DEF(ob, name, doc, methods) \
          static struct PyModuleDef moduledef = { \
            PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
          ob = PyModule_Create(&moduledef);
#endif

MOD_INIT(pycryptsetup);

typedef struct {
	PyObject_HEAD

	/* Type-specific fields go here. */
	struct crypt_device *device;
	char *activated_as;

	/* Callbacks */
	PyObject *yesDialogCB;
	PyObject *cmdLineLogCB;
	PyObject *passwordDialogCB;
} CryptSetupObject;

static int yesDialog(const char *msg, void *this)
{
	CryptSetupObject *self = this;
	PyObject *result, *arglist;
	int r;

	if (self->yesDialogCB){
		arglist = Py_BuildValue("(s)", msg);
		if (!arglist)
			return -ENOMEM;

		result = PyEval_CallObject(self->yesDialogCB, arglist);
		Py_DECREF(arglist);

		if (!result)
			return -EINVAL;

		if (!PyArg_Parse(result, "i", &r))
			r = -EINVAL;

		Py_DECREF(result);
		return r;
	}

	return 1;
}

static int passwordDialog(const char *msg, char *buf, size_t length, void *this)
{
	CryptSetupObject *self = this;
	PyObject *result, *arglist;
	size_t len;
	char *res = NULL;

	if(self->passwordDialogCB){
		arglist = Py_BuildValue("(s)", msg);
		if (!arglist)
			return -ENOMEM;

		result = PyEval_CallObject(self->passwordDialogCB, arglist);
		Py_DECREF(arglist);

		if (!result)
			return -EINVAL;

		if (!PyArg_Parse(result, "z", &res)) {
			Py_DECREF(result);
			return -EINVAL;
		}

		strncpy(buf, res, length - 1);
		len = strlen(res);

		memset(res, 0, len);
		Py_DECREF(result);

		return (int)len;
	}

	return -EINVAL;
}

static void cmdLineLog(int cls, const char *msg, void *this)
{
	CryptSetupObject *self = this;
	PyObject *result, *arglist;

	if(self->cmdLineLogCB) {
		arglist = Py_BuildValue("(is)", cls, msg);
		if(!arglist)
			return;

		result = PyEval_CallObject(self->cmdLineLogCB, arglist);
		Py_DECREF(arglist);
		Py_XDECREF(result);
	}
}

static void CryptSetup_dealloc(CryptSetupObject* self)
{
	/* free the callbacks */
	Py_XDECREF(self->yesDialogCB);
	Py_XDECREF(self->cmdLineLogCB);
	Py_XDECREF(self->passwordDialogCB);

	free(self->activated_as);

	crypt_free(self->device);

	/* free self */
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *CryptSetup_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	CryptSetupObject *self = (CryptSetupObject *)type->tp_alloc(type, 0);

	if (self) {
		self->yesDialogCB = NULL;
		self->passwordDialogCB = NULL;
		self->cmdLineLogCB = NULL;
		self->activated_as = NULL;
	}

	return (PyObject *)self;
}

static PyObject *PyObjectResult(int is)
{
	PyObject *result = Py_BuildValue("i", is);

	if (!result)
		PyErr_SetString(PyExc_RuntimeError, "Error during constructing values for return value");

	return result;
}

static char
CryptSetup_HELP[] =
"CryptSetup object\n\n\
constructor takes one to five arguments:\n\
  __init__(device, name, yesDialog, passwordDialog, logFunc)\n\n\
  yesDialog - python function with func(text) signature, \n\
              which asks the user question text and returns 1\n\
              of the answer was positive or 0 if not\n\
  logFunc   - python function with func(level, text) signature to log stuff somewhere";

static int CryptSetup_init(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"device", "name", "yesDialog", "passwordDialog", "logFunc", NULL};
	PyObject *yesDialogCB = NULL,
		 *passwordDialogCB = NULL,
		 *cmdLineLogCB = NULL,
		 *tmp = NULL;
	char *device = NULL, *deviceName = NULL;
	int r;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zzOOO", CONST_CAST(char**)kwlist, &device, &deviceName,
					 &yesDialogCB, &passwordDialogCB, &cmdLineLogCB))
		return -1;

	if (device) {
		if (crypt_init(&(self->device), device)) {
			PyErr_SetString(PyExc_IOError, "Device cannot be opened");
			return -1;
		}
		/* Try to load header form device */
		r = crypt_load(self->device, NULL, NULL);
		if (r && r != -EINVAL) {
			PyErr_SetString(PyExc_RuntimeError, "Cannot initialize device context");
			return -1;
		}
	} else if (deviceName) {
		if (crypt_init_by_name(&(self->device), deviceName)) {
			PyErr_SetString(PyExc_IOError, "Device cannot be opened");
			return -1;
		}
		/* Context is initialized automatically from active device */
	} else {
		PyErr_SetString(PyExc_RuntimeError, "Either device file or luks name has to be specified");
		return -1;
	}

	if(deviceName)
		self->activated_as = strdup(deviceName);

	if (yesDialogCB) {
		tmp = self->yesDialogCB;
		Py_INCREF(yesDialogCB);
		self->yesDialogCB = yesDialogCB;
		Py_XDECREF(tmp);
		crypt_set_confirm_callback(self->device, yesDialog, self);
	}

	if (passwordDialogCB) {
		tmp = self->passwordDialogCB;
		Py_INCREF(passwordDialogCB);
		self->passwordDialogCB = passwordDialogCB;
		Py_XDECREF(tmp);
		crypt_set_password_callback(self->device, passwordDialog, self);
	}

	if (cmdLineLogCB) {
		tmp = self->cmdLineLogCB;
		Py_INCREF(cmdLineLogCB);
		self->cmdLineLogCB = cmdLineLogCB;
		Py_XDECREF(tmp);
		crypt_set_log_callback(self->device, cmdLineLog, self);
	}

	return 0;
}

static char
CryptSetup_activate_HELP[] =
"Activate LUKS device\n\n\
  activate(name)";

static PyObject *CryptSetup_activate(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"name", "passphrase", NULL};
	char *name = NULL, *passphrase = NULL;
	int is;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|s", CONST_CAST(char**)kwlist, &name, &passphrase))
		return NULL;

	// FIXME: allow keyfile and \0 in passphrase
	is = crypt_activate_by_passphrase(self->device, name, CRYPT_ANY_SLOT,
					  passphrase, passphrase ? strlen(passphrase) : 0, 0);

	if (is >= 0) {
		free(self->activated_as);
		self->activated_as = strdup(name);
	}

	return PyObjectResult(is);
}

static char
CryptSetup_deactivate_HELP[] =
"Dectivate LUKS device\n\n\
  deactivate()";

static PyObject *CryptSetup_deactivate(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	int is = crypt_deactivate(self->device, self->activated_as);

	if (!is) {
		free(self->activated_as);
		self->activated_as = NULL;
	}

	return PyObjectResult(is);
}

static char
CryptSetup_askyes_HELP[] =
"Asks a question using the configured dialog CB\n\n\
  int askyes(message)";

static PyObject *CryptSetup_askyes(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"message", NULL};
	PyObject *message = NULL, *result, *arglist;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", CONST_CAST(char**)kwlist, &message))
		return NULL;

	Py_INCREF(message);

	arglist = Py_BuildValue("(O)", message);
	if (!arglist){
		PyErr_SetString(PyExc_RuntimeError, "Error during constructing values for internal call");
		return NULL;
	}

	result = PyEval_CallObject(self->yesDialogCB, arglist);
	Py_DECREF(arglist);
	Py_DECREF(message);

	return result;
}

static char
CryptSetup_log_HELP[] =
"Logs a string using the configured log CB\n\n\
  log(int level, message)";

static PyObject *CryptSetup_log(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"priority", "message", NULL};
	PyObject *message = NULL, *priority = NULL, *result, *arglist;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", CONST_CAST(char**)kwlist, &message, &priority))
		return NULL;

	Py_INCREF(message);
	Py_INCREF(priority);

	arglist = Py_BuildValue("(OO)", message, priority);
	if (!arglist){
		PyErr_SetString(PyExc_RuntimeError, "Error during constructing values for internal call");
		return NULL;
	}

	result = PyEval_CallObject(self->cmdLineLogCB, arglist);
	Py_DECREF(arglist);
	Py_DECREF(priority);
	Py_DECREF(message);

	return result;
}

static char
CryptSetup_luksUUID_HELP[] =
"Get UUID of the LUKS device\n\n\
  luksUUID()";

static PyObject *CryptSetup_luksUUID(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	PyObject *result;

	result = Py_BuildValue("s", crypt_get_uuid(self->device));
	if (!result)
		PyErr_SetString(PyExc_RuntimeError, "Error during constructing values for return value");

	return result;
}

static char
CryptSetup_isLuks_HELP[] =
"Is the device LUKS?\n\n\
  isLuks()";

static PyObject *CryptSetup_isLuks(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	return PyObjectResult(crypt_load(self->device, CRYPT_LUKS1, NULL));
}

static char
CryptSetup_Info_HELP[] =
"Returns dictionary with info about opened device\nKeys:\n\
  dir\n  name\n  uuid\n  cipher\n  cipher_mode\n  keysize\n  device\n\
  offset\n  size\n  skip\n  mode\n";

static PyObject *CryptSetup_Info(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	PyObject *result;

	result = Py_BuildValue("{s:s,s:s,s:z,s:s,s:s,s:s,s:i,s:K}",
				"dir",		crypt_get_dir(),
				"device",	crypt_get_device_name(self->device),
				"name",		self->activated_as,
				"uuid",		crypt_get_uuid(self->device),
				"cipher",	crypt_get_cipher(self->device),
				"cipher_mode",	crypt_get_cipher_mode(self->device),
				"keysize",	crypt_get_volume_key_size(self->device) * 8,
				//"size",	co.size,
				//"mode",	(co.flags & CRYPT_FLAG_READONLY) ? "readonly" : "read/write",
				"offset",	crypt_get_data_offset(self->device)
				);

	if (!result)
		PyErr_SetString(PyExc_RuntimeError, "Error during constructing values for return value");

	return result;
}

static char
CryptSetup_luksFormat_HELP[] =
"Format device to enable LUKS\n\n\
  luksFormat(cipher = 'aes', cipherMode = 'cbc-essiv:sha256', keysize = 256)\n\n\
  cipher - cipher specification, e.g. aes, serpent\n\
  cipherMode - cipher mode specification, e.g. cbc-essiv:sha256, xts-plain64\n\
  keysize - key size in bits";

static PyObject *CryptSetup_luksFormat(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"cipher", "cipherMode", "keysize", NULL};
	char *cipher_mode = NULL, *cipher = NULL;
	int keysize = 256;
	PyObject *keysize_object = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zzO", CONST_CAST(char**)kwlist,
					&cipher, &cipher_mode, &keysize_object))
		return NULL;

	if (!keysize_object || keysize_object == Py_None) {
		/* use default value */
	} else if (!PyInt_Check(keysize_object)) {
		PyErr_SetString(PyExc_TypeError, "keysize must be an integer");
		return NULL;
	} else if (PyInt_AsLong(keysize_object) % 8) {
		PyErr_SetString(PyExc_TypeError, "keysize must have integer value dividable by 8");
		return NULL;
	} else if (PyInt_AsLong(keysize_object) <= 0) {
		PyErr_SetString(PyExc_TypeError, "keysize must be positive number bigger than 0");
		return NULL;
	} else
		keysize = PyInt_AsLong(keysize_object);

	// FIXME use #defined defaults
	return PyObjectResult(crypt_format(self->device, CRYPT_LUKS1,
				cipher ?: "aes", cipher_mode ?: "cbc-essiv:sha256",
				NULL, NULL, keysize / 8, NULL));
}

static char
CryptSetup_addKeyByPassphrase_HELP[] =
"Initialize keyslot using passphrase\n\n\
  addKeyByPassphrase(passphrase, newPassphrase, slot)\n\n\
  passphrase - string or none to ask the user\n\
  newPassphrase - passphrase to add\n\
  slot - which slot to use (optional)";

static PyObject *CryptSetup_addKeyByPassphrase(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"passphrase", "newPassphrase", "slot", NULL};
	char *passphrase = NULL, *newpassphrase = NULL;
	size_t passphrase_len = 0, newpassphrase_len = 0;
	int slot = CRYPT_ANY_SLOT;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss|i", CONST_CAST(char**)kwlist, &passphrase, &newpassphrase, &slot))
		return NULL;

	if(passphrase)
		passphrase_len = strlen(passphrase);

	if(newpassphrase)
		newpassphrase_len = strlen(newpassphrase);

	return PyObjectResult(crypt_keyslot_add_by_passphrase(self->device, slot,
					passphrase, passphrase_len,
					newpassphrase, newpassphrase_len));
}

static char
CryptSetup_addKeyByVolumeKey_HELP[] =
"Initialize keyslot using cached volume key\n\n\
  addKeyByVolumeKey(passphrase, newPassphrase, slot)\n\n\
  newPassphrase - passphrase to add\n\
  slot - which slot to use (optional)";

static PyObject *CryptSetup_addKeyByVolumeKey(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"newPassphrase", "slot", NULL};
	char *newpassphrase = NULL;
	size_t newpassphrase_len = 0;
	int slot = CRYPT_ANY_SLOT;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|i", CONST_CAST(char**)kwlist, &newpassphrase, &slot))
		return NULL;

	if (newpassphrase)
		newpassphrase_len = strlen(newpassphrase);

	return PyObjectResult(crypt_keyslot_add_by_volume_key(self->device, slot,
					NULL, 0, newpassphrase, newpassphrase_len));
}

static char
CryptSetup_removePassphrase_HELP[] =
"Destroy keyslot using passphrase\n\n\
  removePassphrase(passphrase)\n\n\
  passphrase - string or none to ask the user";

static PyObject *CryptSetup_removePassphrase(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"passphrase", NULL};
	char *passphrase = NULL;
	size_t passphrase_len = 0;
	int is;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", CONST_CAST(char**)kwlist, &passphrase))
		return NULL;

	if (passphrase)
		passphrase_len = strlen(passphrase);

	is = crypt_activate_by_passphrase(self->device, NULL, CRYPT_ANY_SLOT,
					  passphrase, passphrase_len, 0);
	if (is < 0)
		return PyObjectResult(is);

	return PyObjectResult(crypt_keyslot_destroy(self->device, is));
}

static char
CryptSetup_killSlot_HELP[] =
"Destroy keyslot\n\n\
  killSlot(slot)\n\n\
  slot - the slot to remove";

static PyObject *CryptSetup_killSlot(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"slot", NULL};
	int slot = CRYPT_ANY_SLOT;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", CONST_CAST(char**)kwlist, &slot))
		return NULL;

	switch (crypt_keyslot_status(self->device, slot)) {
	case CRYPT_SLOT_ACTIVE:
		return PyObjectResult(crypt_keyslot_destroy(self->device, slot));
	case CRYPT_SLOT_ACTIVE_LAST:
		PyErr_SetString(PyExc_ValueError, "Last slot, removing it would render the device unusable");
		break;
	case CRYPT_SLOT_INACTIVE:
		PyErr_SetString(PyExc_ValueError, "Inactive slot");
		break;
	case CRYPT_SLOT_INVALID:
		PyErr_SetString(PyExc_ValueError, "Invalid slot");
		break;
	}

	return NULL;
}

static char
CryptSetup_Status_HELP[] =
"Status of LUKS device\n\n\
  luksStatus()";

static PyObject *CryptSetup_Status(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	if (!self->activated_as){
		PyErr_SetString(PyExc_IOError, "Device has not been activated yet.");
		return NULL;
	}

	return PyObjectResult(crypt_status(self->device, self->activated_as));
}

static char
CryptSetup_Resume_HELP[] =
"Resume LUKS device\n\n\
  luksOpen(passphrase)\n\n\
  passphrase - string or none to ask the user";

static PyObject *CryptSetup_Resume(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"passphrase", NULL};
	char* passphrase = NULL;
	size_t passphrase_len = 0;

	if (!self->activated_as){
		PyErr_SetString(PyExc_IOError, "Device has not been activated yet.");
		return NULL;
	}

	if (! PyArg_ParseTupleAndKeywords(args, kwds, "|s", CONST_CAST(char**)kwlist, &passphrase))
		return NULL;

	if (passphrase)
		passphrase_len = strlen(passphrase);

	return PyObjectResult(crypt_resume_by_passphrase(self->device, self->activated_as,
					CRYPT_ANY_SLOT, passphrase, passphrase_len));
}

static char
CryptSetup_Suspend_HELP[] =
"Suspend LUKS device\n\n\
  luksSupsend()";

static PyObject *CryptSetup_Suspend(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	if (!self->activated_as){
		PyErr_SetString(PyExc_IOError, "Device has not been activated yet.");
		return NULL;
	}

	return PyObjectResult(crypt_suspend(self->device, self->activated_as));
}

static char
CryptSetup_debugLevel_HELP[] =
"Set debug level\n\n\
  debugLevel(level)\n\n\
  level - debug level";

static PyObject *CryptSetup_debugLevel(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"level", NULL};
	int level = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", CONST_CAST(char**)kwlist, &level))
		return NULL;

	crypt_set_debug_level(level);

	Py_RETURN_NONE;
}

static char
CryptSetup_iterationTime_HELP[] =
"Set iteration time\n\n\
  iterationTime(time_ms)\n\n\
  time_ms - time in miliseconds";

static PyObject *CryptSetup_iterationTime(CryptSetupObject* self, PyObject *args, PyObject *kwds)
{
	static const char *kwlist[] = {"time_ms", NULL};
	uint64_t time_ms = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "K", CONST_CAST(char**)kwlist, &time_ms))
		return NULL;

	crypt_set_iteration_time(self->device, time_ms);

	Py_RETURN_NONE;
}

static PyMemberDef CryptSetup_members[] = {
	{CONST_CAST(char*)"yesDialogCB", T_OBJECT_EX, offsetof(CryptSetupObject, yesDialogCB), 0, CONST_CAST(char*)"confirmation dialog callback"},
	{CONST_CAST(char*)"cmdLineLogCB", T_OBJECT_EX, offsetof(CryptSetupObject, cmdLineLogCB), 0, CONST_CAST(char*)"logging callback"},
	{CONST_CAST(char*)"passwordDialogCB", T_OBJECT_EX, offsetof(CryptSetupObject, passwordDialogCB), 0, CONST_CAST(char*)"password dialog callback"},
	{NULL}
};

static PyMethodDef CryptSetup_methods[] = {
	/* self-test methods */
	{"log", (PyCFunction)CryptSetup_log, METH_VARARGS|METH_KEYWORDS, CryptSetup_askyes_HELP},
	{"askyes", (PyCFunction)CryptSetup_askyes, METH_VARARGS|METH_KEYWORDS, CryptSetup_log_HELP},

	/* activation and deactivation */
	{"deactivate", (PyCFunction)CryptSetup_deactivate, METH_NOARGS, CryptSetup_deactivate_HELP},
	{"activate", (PyCFunction)CryptSetup_activate, METH_VARARGS|METH_KEYWORDS, CryptSetup_activate_HELP},

	/* cryptsetup info entrypoints */
	{"luksUUID", (PyCFunction)CryptSetup_luksUUID, METH_NOARGS, CryptSetup_luksUUID_HELP},
	{"isLuks", (PyCFunction)CryptSetup_isLuks, METH_NOARGS, CryptSetup_isLuks_HELP},
	{"info", (PyCFunction)CryptSetup_Info, METH_NOARGS, CryptSetup_Info_HELP},
	{"status", (PyCFunction)CryptSetup_Status, METH_NOARGS, CryptSetup_Status_HELP},

	/* cryptsetup mgmt entrypoints */
	{"luksFormat", (PyCFunction)CryptSetup_luksFormat, METH_VARARGS|METH_KEYWORDS, CryptSetup_luksFormat_HELP},
	{"addKeyByPassphrase", (PyCFunction)CryptSetup_addKeyByPassphrase, METH_VARARGS|METH_KEYWORDS, CryptSetup_addKeyByPassphrase_HELP},
	{"addKeyByVolumeKey", (PyCFunction)CryptSetup_addKeyByVolumeKey, METH_VARARGS|METH_KEYWORDS, CryptSetup_addKeyByVolumeKey_HELP},
	{"removePassphrase", (PyCFunction)CryptSetup_removePassphrase, METH_VARARGS|METH_KEYWORDS, CryptSetup_removePassphrase_HELP},
	{"killSlot", (PyCFunction)CryptSetup_killSlot, METH_VARARGS|METH_KEYWORDS, CryptSetup_killSlot_HELP},

	/* suspend resume */
	{"resume", (PyCFunction)CryptSetup_Resume, METH_VARARGS|METH_KEYWORDS, CryptSetup_Resume_HELP},
	{"suspend", (PyCFunction)CryptSetup_Suspend, METH_NOARGS, CryptSetup_Suspend_HELP},

	/* misc */
	{"debugLevel", (PyCFunction)CryptSetup_debugLevel, METH_VARARGS|METH_KEYWORDS, CryptSetup_debugLevel_HELP},
	{"iterationTime", (PyCFunction)CryptSetup_iterationTime, METH_VARARGS|METH_KEYWORDS, CryptSetup_iterationTime_HELP},

	{NULL} /* Sentinel */
};

static PyTypeObject CryptSetupType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"pycryptsetup.CryptSetup", /*tp_name*/
	sizeof(CryptSetupObject), /*tp_basicsize*/
	0, /*tp_itemsize*/
	(destructor)CryptSetup_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	0, /*tp_getattr*/
	0, /*tp_setattr*/
	0, /*tp_compare*/
	0, /*tp_repr*/
	0, /*tp_as_number*/
	0, /*tp_as_sequence*/
	0, /*tp_as_mapping*/
	0, /*tp_hash */
	0, /*tp_call*/
	0, /*tp_str*/
	0, /*tp_getattro*/
	0, /*tp_setattro*/
	0, /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	CryptSetup_HELP, /* tp_doc */
	0, /* tp_traverse */
	0, /* tp_clear */
	0, /* tp_richcompare */
	0, /* tp_weaklistoffset */
	0, /* tp_iter */
	0, /* tp_iternext */
	CryptSetup_methods, /* tp_methods */
	CryptSetup_members, /* tp_members */
	0, /* tp_getset */
	0, /* tp_base */
	0, /* tp_dict */
	0, /* tp_descr_get */
	0, /* tp_descr_set */
	0, /* tp_dictoffset */
	(initproc)CryptSetup_init, /* tp_init */
	0, /* tp_alloc */
	CryptSetup_new, /* tp_new */
};

static PyMethodDef pycryptsetup_methods[] = {
	{NULL} /* Sentinel */
};

MOD_INIT(pycryptsetup)
{
	PyObject *m;

	if (PyType_Ready(&CryptSetupType) < 0)
		return MOD_ERROR_VAL;

	MOD_DEF(m, "pycryptsetup", "CryptSetup pythonized API.", pycryptsetup_methods);
	Py_INCREF(&CryptSetupType);

	PyModule_AddObject(m, "CryptSetup", (PyObject *)&CryptSetupType);

	/* debug constants */
	PyModule_AddIntConstant(m, "CRYPT_DEBUG_ALL", CRYPT_DEBUG_ALL);
	PyModule_AddIntConstant(m, "CRYPT_DEBUG_NONE", CRYPT_DEBUG_NONE);

	/* log constants */
	PyModule_AddIntConstant(m, "CRYPT_LOG_NORMAL", CRYPT_LOG_NORMAL);
	PyModule_AddIntConstant(m, "CRYPT_LOG_ERROR", CRYPT_LOG_ERROR);
	PyModule_AddIntConstant(m, "CRYPT_LOG_VERBOSE", CRYPT_LOG_VERBOSE);
	PyModule_AddIntConstant(m, "CRYPT_LOG_DEBUG", CRYPT_LOG_DEBUG);

	/* status constants */
	PyModule_AddIntConstant(m, "CRYPT_INVALID", CRYPT_INVALID);
	PyModule_AddIntConstant(m, "CRYPT_INACTIVE", CRYPT_INACTIVE);
	PyModule_AddIntConstant(m, "CRYPT_ACTIVE", CRYPT_ACTIVE);
	PyModule_AddIntConstant(m, "CRYPT_BUSY", CRYPT_BUSY);

	return MOD_SUCCESS_VAL(m);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libcryptsetup.h>

#include "crypt_examples.h"

#define KEY_SIZE 32
#define EX_DEV_NAME "ex_crypt_dev"
#define DMDIR "/dev/mapper/"
#define SECTOR_SIZE 512

/*
 * You can use this example with command line parameters as follows,
 * but please note, that this example will not do any sophisticated parameters
 * checking at all.
 *
 * ./crypt_luks_usage <path>
 *
 * 	where:
 * 	<path> is either regular file or block device. DO NOT use your physical HDD
 * 	with running system or another device containing valuable data otherwise you risk
 * 	partial or complete loss of it.
 */
static void usage(const char *msg)
{
	fprintf(stderr, "ERROR: %s\nusage: ./crypt_luks_usage <path>\n"
			"The <path> can refer to either a regular file or a block device.\n",
			msg ?: "");
}

int main(int argc, char **argv)
{
	char *answer = NULL, *cipher, *cipher_mode, *dev;
	int step = 0, r;
	size_t size = 0;
	/* crypt device handle */
	struct crypt_active_device cad;
	struct crypt_device *cd;
	struct crypt_params_luks1 params;

	if (geteuid())
		fprintf(stderr, "WARN: Process doesn't have super user privileges. "
				"Most of examples will fail because of that.\n");

	if (argc != 2) {
		usage("Wrong number of cmd line parameters.");
		exit(1);
	}

	dev = argv[1];

	/*
	 * __STEP_01__
	 *
	 * crypt_init() call precedes most of operations of cryptsetup API. The call is used
	 * to initialize crypt device context stored in structure referenced by _cd_ in
	 * the example. Second parameter is used to pass underlaying device path.
	 *
	 * Note:
	 * If path refers to a regular file it'll be attached to a first free loop device.
	 * crypt_init() operation fails in case there's no more loop device available.
	 * Also, loop device will have the AUTOCLEAR flag set, so the file will be
	 * detached after crypt_free() call on the concerned context.
	 */
	EX_STEP(++step, "crypt_init()");
	if ((r = crypt_init(&cd, dev))) {
		EX_FAIL("crypt_init() failed for '%s'\n", dev ?: "(not set)");
		return r;
	}
	EX_SUCCESS("crypt_init() on '%s' has been successful", dev);
	if (strcmp(dev, crypt_get_device_name(cd)))
		printf("\tFile '%s' has been attached to %s\n", dev, crypt_get_device_name(cd));

	EX_DELIM;
	/*
	 * So far no data were written on your device. This will change with call of
	 * crypt_format() only if you specify CRYPT_LUKS1 as device type.
	 */
	printf("8 initial sectors of the device will be overwritten\n"
	       "Are you sure you want to call crypt_format() over '%s'?\n"
	       "If you're absolutely sure the device doesn't contain any valuable data,\n"
	       "approve the operation by typing 'yes' in upper case: ", crypt_get_device_name(cd));

	if ((r = getline(&answer, &size, stdin)) == -1) {
		perror("getline");
		goto out;
	}

	if (strcmp(answer, "YES\n"))
		goto out;

	/* Example of crypt_format() follows: */

	/*
	 * cipher and cipher_mode:
	 *
	 * you'll get more on _cipher_ and _cipher_mode_ in man page
	 * for cryptsetup userspace utility or at cryptsetup project
	 * documentation.
	 */
	cipher = "aes";
	cipher_mode = "cbc-essiv:sha256";
	params.hash = "sha1";

	/*
	 * This parameter is relevant only in case of the luks header
	 * and the payload are both stored on same device.
	 *
	 * In this particular case, payload offset (which is
	 * computed internaly, according to volume key size)
	 * is aligned to 2048 sectors
	 *
	 * if you set data_alignment = 0, cryptsetup will autodetect
	 * data_alignment from underlaying device topology.
	 */
	params.data_alignment = 2048;

	/*
	 * this parameter defines that no external device
	 * for luks header will be used
	 */
	params.data_device = NULL;

	/*
	 * __STEP_02__
	 *
	 * NULLs for uuid and volume_key means that these attributes will be
	 * generated during crypt_format(). Volume key is generated with respect
	 * to key size parameter passed to function.
	 *
	 * Note that in crypt_format() device is checked wheter it's large enough to
	 * store the luks header only.
	 */
	EX_STEP(++step, "crypt_format()");
	if((r = crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, NULL, KEY_SIZE, &params))) {
		EX_FAIL("crypt_format() failed on device %s\n", crypt_get_device_name(cd));
		goto out;
	}
	EX_SUCCESS("crypt_format() on device %s formated successfully. "
			"The device now contains LUKS1 header, but there is no active keyslot with encrypted "
			"volume key.", crypt_get_device_name(cd));
	EX_DELIM;

	/*
	 * __STEP_03__
	 *
	 * This call is intended to store volume_key in encrypted form into structure called keyslot.
	 * Without keyslot you can't manipulate with LUKS device after the context will be freed.
	 *
	 * To create a new keyslot you need to supply the existing one (to get the volume key from) or
	 * you need to supply the volume key. Now we have volume key stored internally and we have no active
	 * keyslot so this the only option.
	 *
	 */
	printf("Going to create a new keyslot...\n");
	EX_STEP(++step, "crypt_keyslot_add_by_volume_key()");
	if ((r = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL, 0, NULL, 0)) < 0) {
		EX_FAIL("Adding keyslot failed.");
		goto out;
	}
	EX_SUCCESS("Keyslot nr. %d created successfully on device %s.", r, crypt_get_device_name(cd));
	EX_DELIM;

	/*
	 * __STEP_04__
	 *
	 * This is the example of the second method mentioned in STEP 03. By supplying passphrase for
	 * the active keyslot you can create a new one.
	 */
	printf("Now let's try to add a keyslot using the existing active keyslot\n");
	EX_STEP(++step, "crypt_keyslot_add_by_passphrase()");
	if ((r = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, NULL, 0, NULL, 0)) < 0) {
		EX_FAIL("Adding keyslot failed\n");
		goto out;
	}
	EX_SUCCESS("Keyslot nr. %d created successfully and written on device %s.", r, crypt_get_device_name(cd));
	EX_DELIM;

	crypt_free(cd);
	cd = NULL;

	/*
	 * __STEP_05__
	 *
	 * In previous steps the device was formatted (LUKS header was written to backing device)
	 * and keyslots were activated (volume key was written in two separate structures encrypted
	 * by two user supplied passwords).
	 *
	 * This example demonstrates typical use case for LUKS device activation.
	 * It's sequence of sub-steps: device initialization (crypt_init), LUKS header load (crypt_load())
	 * and finally the device activation itself
	 */
	EX_PRESS_ENTER("Device context going to be freed. New one will initialized to demonstrate activation process.");
	EX_STEP(++step, "crypt_init()");
	if ((r = crypt_init(&cd, dev))) {
		EX_FAIL("crypt_init() failed for '%s'!", dev);
		goto out;
	}
	EX_SUCCESS("crypt_init() on '%s' has been successful.", dev);
	if (strcmp(dev, crypt_get_device_name(cd)))
		printf("\tFile '%s' has been attached to %s\n", dev, crypt_get_device_name(cd));
	EX_DELIM;
	/* __STEP_05__
	 *
	 * crypt_load() is used to load the LUKS header from backing block device
	 * into crypt_device context
	 */
	EX_PRESS_ENTER("Going to load LUKS header.");
	EX_STEP(step, "crypt_load()");
	if ((r = crypt_load(cd, CRYPT_LUKS1, &params))) {
		EX_FAIL("crypt_load() failed on device '%s'!", crypt_get_device_name(cd));
		goto out;
	}
	EX_SUCCESS("crypt_load() successful. The header has been read from %s.", crypt_get_device_name(cd));
	EX_DELIM;

	/*
	 * __STEP_05__
	 *
	 * Device activation creates mapping in device-mapper with name EX_DEV_NAME.
	 * The volume key is stored into kernel mem. space and the encryption of backing
	 * device is now set in motion.
	 */
	printf("Going to activate LUKS device\n");
	EX_STEP(step, "crypt_activate_by_passphrase()");
	if ((r = crypt_activate_by_passphrase(cd, EX_DEV_NAME, CRYPT_ANY_SLOT, NULL, 0, 0)) < 0) {
		EX_FAIL("Device activation failed!");
		goto out;
	}
	EX_SUCCESS("Encrypted device is active on " DMDIR EX_DEV_NAME ".");
	printf("\tThe cipher used in device context: '%s'\n", crypt_get_cipher(cd) ?: "(not set) !");
	printf("\tThe cipher mode used in device context: '%s'\n", crypt_get_cipher_mode(cd) ?: "(not set) !");
	printf("\tThe device UUID '%s'\n", crypt_get_uuid(cd) ?: "(not set) !");
	EX_DELIM;

	/*
	 * __STEP_06__
	 *
	 * Get info about active device (query DM backend)
	 */
	EX_PRESS_ENTER("Going to get active active device parameters.");
	EX_STEP(++step, "crypt_get_active_device()");
	if ((r = crypt_get_active_device(cd, EX_DEV_NAME, &cad))) {
		EX_FAIL("Get info about active device '%s' failed!", EX_DEV_NAME);
		goto out;
	}
	EX_SUCCESS("Active device parameters for " EX_DEV_NAME ":\n"
			"\tPayload offset (in sectors): %" PRIu64 "\n"
			"\tEncrypted payload area size in sectors: %" PRIu64 " and bytes: %" PRIu64 "\n"
			"\tThe device has a read-only flag %sset",
			cad.offset, cad.size, cad.size * SECTOR_SIZE,
			cad.flags & CRYPT_ACTIVATE_READONLY ? "" : "not ");
	EX_DELIM;

	crypt_free(cd);
	cd = NULL;

	/*
	 * __STEP_07__
	 *
	 * crypt_init_by_name() initializes device context and loads LUKS header from backing device
	 */
	EX_PRESS_ENTER("The context used in previous examples is going to be freed to demonstrate "
			"how to initialize a device context from the active device.");
	EX_STEP(++step, "crypt_init_by_name()");
	if ((r = crypt_init_by_name(&cd, EX_DEV_NAME))) {
		EX_FAIL("crypt_init_by_name() failed for the device name: " EX_DEV_NAME);
		goto out;
	}
	EX_SUCCESS("A new context has been initialized, LUKS header has been restored"
			"\n\tDevice UUID is '%s'", crypt_get_uuid(cd));

	/*
	 * __STEP_08__
	 *
	 * crypt_deactivate() is used to remove the volume_key from kernel mem. space and to remove the
	 * device nod associated with decrypted backing device.
	 *
	 */
	EX_PRESS_ENTER("\n\tGoing to deactivate the crypt device. Note that the device "
			"won't be deactivated while it's opened with O_EXCL flag (e.g. mounted).");
	EX_STEP(++step, "crypt_deactivate()");
	//printf("\nPress <ENTER> to continue to device deactivation of the test device.\n"
	//	"Note that mounted device won't be deactivated. First unmount the device!");
	//getc(stdin);
	while ((r = crypt_deactivate(cd, EX_DEV_NAME))) {
		EX_FAIL("crypt_deactivate() failed. Most propably the device is still busy!");
		EX_PRESS_ENTER("Going to retry device deactivation");
	}
	EX_SUCCESS("crypt_deactivate() successful. Device " DMDIR EX_DEV_NAME " is now deactivated");

out:
	if (crypt_status(cd, EX_DEV_NAME) == CRYPT_ACTIVE)
		crypt_deactivate(cd, EX_DEV_NAME);
	if (answer)
		free(answer);
	/* always free context which is no longer used  */
	if (cd)
		crypt_free(cd);

	return r;
}

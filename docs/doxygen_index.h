/*! \mainpage Cryptsetup API
 *
 * <b>The</b> documentation covers public parts of cryptsetup API. In the following sections you'll find
 * the examples that describe some features of cryptsetup API.
 * For more info about libcryptsetup API versions see
 * <a href="https://gitlab.com/cryptsetup/cryptsetup/wikis/ABI-tracker/timeline/libcryptsetup/index.html">API Tracker</a>.
 *
 * <OL type="A">
 *	<LI>@ref cexamples "Cryptsetup API examples"</LI>
 *	<OL type="1">
 *		<LI>@ref cluks "crypt_luks_usage" - cryptsetup LUKS device type usage examples</LI>
 *			<UL>
 *				<LI>@ref cinit "crypt_init()"</LI>
 *				<LI>@ref cformat "crypt_format()" - header and payload on mutual device</LI>
 *				<LI>@ref ckeys "Keyslot operations" </LI>
 *				<UL>
 *					<LI>@ref ckeyslot_vol "crypt_keyslot_add_by_volume_key()"</LI>
 *					<LI>@ref ckeyslot_pass "crypt_keyslot_add_by_passphrase()"</LI>
 *				</UL>
 *				<LI>@ref cload "crypt_load()"
 *				<LI>@ref cactivate "crypt_activate_by_passphrase()"</LI>
 *				<LI>@ref cactive_pars "crypt_get_active_device()"</LI>
 *				<LI>@ref cinit_by_name "crypt_init_by_name()"</LI>
 *				<LI>@ref cdeactivate "crypt_deactivate()"</LI>
 *				<LI>@ref cluks_ex "crypt_luks_usage.c"</LI>
 *			</UL>
 *		<LI>@ref clog "crypt_log_usage" - cryptsetup logging API examples</LI>
 *	</OL>
 * </OL>
 *
 * @section cexamples Cryptsetup API examples
 * 	@section cluks crypt_luks_usage - cryptsetup LUKS device type usage
 *	 	@subsection cinit crypt_init()
 *			Every time you need to do something with cryptsetup or dmcrypt device
 *			you need a valid context. The first step to start your work is
 *			@ref crypt_init call. You can call it either with path
 *			to the block device or path to the regular file. If you don't supply the path,
 *			empty context is initialized.
 *
 *		@subsection cformat crypt_format() - header and payload on mutual device
 *	 		This section covers basic use cases for formatting LUKS devices. Format operation
 *			sets device type in context and in case of LUKS header is written at the beginning
 *			of block device. In the example below we use the scenario where LUKS header and data
 *			are both stored on the same device. There's also a possibility to store header and
 *			data separately.
 *
 *			<B>Bear in mind</B> that @ref crypt_format() is destructive operation and it
 *			overwrites part of the backing block device.
 *
 *		@subsection ckeys Keyslot operations examples
 *			After successful @ref crypt_format of LUKS device, volume key is not stored
 *			in a persistent way on the device. Keyslot area is an array beyond LUKS header, where
 *			volume key is stored in the encrypted form using user input passphrase. For more info about
 *			LUKS keyslots and how it's actually protected, please look at
 *			<A HREF="https://gitlab.com/cryptsetup/cryptsetup/wikis/Specification">LUKS specification</A>.
 *			There are two basic methods to create a new keyslot:
 *
 *			@subsection ckeyslot_vol crypt_keyslot_add_by_volume_key()
 *				Creates a new keyslot directly by encrypting volume_key stored in the device
 *				context. Passphrase should be supplied or user is prompted if passphrase param is
 *				NULL.
 *
 *			@subsection ckeyslot_pass crypt_keyslot_add_by_passphrase()
 *				Creates a new keyslot for the volume key by opening existing active keyslot,
 *				extracting volume key from it and storing it into a new keyslot
 *				protected by a new passphrase
 *
 *		@subsection cload crypt_load()
 *			Function loads header from backing block device into device context.
 *
 *		@subsection cactivate crypt_activate_by_passphrase()
 *			Activates crypt device by user supplied password for keyslot containing the volume_key.
 *			If <I>keyslot</I> parameter is set to <I>CRYPT_ANY_SLOT</I> then all active keyslots
 *			are tried one by one until the volume key is found.
 *
 *	 	@subsection cactive_pars crypt_get_active_device()
 *	 		This call returns structure containing runtime attributes of active device.
 *
 *	 	@subsection cinit_by_name crypt_init_by_name()
 *	 		In case you need to do operations with active device (device which already
 *	 		has its corresponding mapping) and you miss valid device context stored in
 *	 		*crypt_device reference, you should use this call. Function tries to
 *	 		get path to backing device from DM, initializes context for it and loads LUKS
 *	 		header.
 *
 *			@subsection cdeactivate crypt_deactivate()
 *			Deactivates crypt device (removes DM mapping and safely erases volume key from kernel).
 *
 *		@subsection cluks_ex crypt_luks_usage.c - Complex example
 *			To compile and run use following commands in examples directory:
 *
 * @code
 * make
 * ./crypt_luks_usage _path_to_[block_device]_file
 * @endcode
 *			Note that you need to have the cryptsetup library compiled. @include crypt_luks_usage.c
 *
 *	@section clog crypt_log_usage - cryptsetup logging API example
 *		Example describes basic use case for cryptsetup logging. To compile and run
 * 		use following commands in examples directory:
 *
 * @code
 * make
 * ./crypt_log_usage
 * @endcode
 *		Note that you need to have the cryptsetup library compiled. @include crypt_log_usage.c
 *
 *		@example crypt_luks_usage.c
 *		@example crypt_log_usage.c
 */

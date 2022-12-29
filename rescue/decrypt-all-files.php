#!/usr/bin/env php
<?php

	# decrypt-all-files.php
	#
	# Copyright (c) 2019-2022, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# ./decrypt-all-files.php <targetdir> [<sourcedir>|<sourcefile>]*
	#
	#
	# description:
	# ============
	#
	# This script can save your precious files in cases where you encrypted them with the
	# Nextcloud Server Side Encryption and still have access to the data directory and the
	# Nextcloud configuration file ("config/config.php"). This script is able to decrypt locally
	# stored files within the data directory. It supports master-key encrypted files, user-key
	# encrypted files and can also use a rescue key (if enabled) and the public sharing key if
	# files had been publicly shared.
	#
	#
	# In order to use the script you have to configure the given values below:
	#
	# DATADIRECTORY           (REQUIRED) this is the location of the data directory of your Nextcloud instance,
	#                         if you copied or moved your data directory then you have to set this value accordingly,
	#                         this directory has to exist and contain the typical file structure of Nextcloud
	#
	# INSTANCEID              (REQUIRED) this is a value from the Nextcloud configuration file,
	#                         there does not seem to be another way to retrieve this value
	#
	# SECRET                  (REQUIRED) this is a value from the Nextcloud configuration file,
	#                         there does not seem to be another way to retrieve this value
	#
	# RECOVERY_PASSWORD       (OPTIONAL) this is the password for the recovery key,
	#                         you can set this value if you activated the recovery feature of your Nextcloud instance,
	#                         leave this value empty if you did not acticate the recovery feature of your Nextcloud instance
	#
	# USER_PASSWORDS          (OPTIONAL) these are the passwords for the user keys,
	#                         you have to set these values if you disabled the master key encryption of your Nextcloud instance,
	#                         you do not have to set these values if you did not disable the master key encryption of your Nextcloud instance,
	#                         each value represents a (username, password) pair and you can set as many pairs as necessary
	#
	#                         Example: if the username was "beispiel" and the password of that user was "example" then the value
	#                                  has to be set as: define("USER_PASSWORDS", ["beispiel" => "example"]);
	#
	# EXTERNAL_STORAGES       (OPTIONAL) these are the mount paths of external folders,
	#                         you have to set these values if you used external storages within your Nextcloud instance,
	#                         each value represents an (external storage, mount path) pair and you can set as many pairs as necessary,
	#                         the external storage name has to be written as found in the "DATADIRECTORY/files_encryption/keys/files/" folder,
	#                         if the external storage belongs to a specific user then the name has to contain the username followed by a slash
	#                         followed by the external storage name as found in the "DATADIRECTORY/$username/files_encryption/keys/files/" folder,
	#                         the external storage has to be mounted by yourself and the corresponding mount path has to be set
	#
	#                         Example: if the external storage name was "sftp" and you mounted the corresponding SFTP folder as "/mnt/sshfs"
	#                                  then the value has to be set as: define("EXTERNAL_STORAGES", ["sftp" => "/mnt/sshfs"]);
	#
	#                         Example: if the external storage name was "sftp", the external storage belonged to the user "admin" and you
	#                                  mounted the corresponding SFTP folder as "/mnt/sshfs" then the value has to be set as:
	#                                  define("EXTERNAL_STORAGES", ["admin/sftp" => "/mnt/sshfs"]);
	#
	# SUPPORT_MISSING_HEADERS (OPTIONAL) this is a value that tells the script if you have encrypted files without headers,
	#                         this configuration is only needed if you have data from a VERY old OwnCloud/Nextcloud instance,
	#                         you probably should not set this value as it will break unencrypted files that may live alongside your encrypted files
	#
	#
	# execution:
	# ==========
	#
	# To execute the script you have to call it in the following way:
	#
	# ./decrypt-all-files.php <targetdir> [<sourcedir>|<sourcefile>]*
	#
	# <targetdir>  (REQUIRED) this is the target directory where the decrypted files get stored,
	#              the target directory has to already exist and should be empty as already-existing files will be skipped,
	#              make sure that there is enough space to store all decrypted files in the target directory
	#
	# <sourcedir>  (OPTIONAL) this is the name of the source folder which shall be decrypted,
	#              the name of the source folder has to be either absolute or relative to the DATADIRECTORY,
	#              if this parameter is not provided then all files in the data directory will be decrypted
	#
	# <sourcefile> (OPTIONAL) this is the name of the source file which shall be decrypted,
	#              the name of the source file has to be either absolute or relative to the DATADIRECTORY,
	#              if this parameter is not provided then all files in the data directory will be decrypted
	#
	# The execution may take a lot of time, depending on the power of your computer and on the number and size of your files.
	# Make sure that the script is able to run without interruption. As of now it does not have a resume feature. On servers you
	# can achieve this by starting the script within a screen session.
	#
	# Also, the script currently does not support the decryption of files in the trashbin that have been deleted from external
	# storage as Nextcloud creates zero byte files when deleting such a file instead of copying over its actual content.

	// ===== USER CONFIGURATION =====

	// debug mode definitions
	define("DEBUG_MODE",         false);
	define("DEBUG_MODE_VERBOSE", false);

	// nextcloud definitions - you can get these values from config/config.php
	define("DATADIRECTORY", "");
	define("INSTANCEID",    "");
	define("SECRET",        "");

	// recovery password definition
	define("RECOVERY_PASSWORD", "");

	// user password definition,
	// replace "username" with the actual usernames and "password" with the actual passwords
	// you can add or remove entries as necessary
	define("USER_PASSWORDS", array_change_key_case(["username" => "password",
	                                                "username" => "password",
	                                                "username" => "password"]));

	// external storage definition,
	// replace "storage" with the actual external storage names and "/mountpath" with the actual external storage mount paths
	// you can add or remove entries as necessary
	define("EXTERNAL_STORAGES", ["storage" => "/mountpath",
	                             "storage" => "/mountpath",
	                             "storage" => "/mountpath"]);

	// missing headers definition
	// this should only be set to TRUE if you have really old encrypted files that do not contain encryption headers,
	// in most cases this will rather break unencrypted files that may live alongside your encrypted files
	define("SUPPORT_MISSING_HEADERS", false);

	##### DO NOT EDIT BELOW THIS LINE #####

	// ===== SYSTEM DEFINITIONS =====

	// block size definitions
	define("BLOCKSIZE", 8192);

        // list of supported ciphers
	define("CIPHER_SUPPORT", ["AES-256-CTR" => 32,
	                          "AES-128-CTR" => 16,
	                          "AES-256-CFB" => 32,
	                          "AES-128-CFB" => 16]);

	// prefix of decrypted external storages
	define("EXTERNAL_PREFIX", "EXTERNAL_");

	// header entries
	define("HEADER_BEGIN",                "HBEGIN");
	define("HEADER_CIPHER",               "cipher");
	define("HEADER_END",                  "HEND");
	define("HEADER_ENCODING",             "encoding");
	define("HEADER_KEYFORMAT",            "keyFormat");
	define("HEADER_OC_ENCRYPTION_MODULE", "oc_encryption_module");
	define("HEADER_SIGNED",               "signed");

	// header values
	define("HEADER_CIPHER_DEFAULT",               "AES-256-CTR");
	define("HEADER_CIPHER_LEGACY",                "AES-128-CFB");
	define("HEADER_ENCODING_BASE64",              "base64");
	define("HEADER_ENCODING_BINARY",              "binary");
	define("HEADER_KEYFORMAT_HASH",               "hash");
	define("HEADER_KEYFORMAT_PASSWORD",           "password");
	define("HEADER_OC_ENCRYPTION_MODULE_DEFAULT", "OC_DEFAULT_MODULE");
	define("HEADER_SIGNED_FALSE",                 "false");
	define("HEADER_SIGNED_TRUE",                  "true");

	// meta entries
	define("META_ENCRYPTED", "encrypted");
	define("META_IV",        "iv");
	define("META_SIGNATURE", "signature");

	// meta entries tags
	define("META_IV_TAG",            "00iv00");
	define("META_PADDING_TAG_LONG",  "xxx");
	define("META_PADDING_TAG_SHORT", "xx");
	define("META_SIGNATURE_TAG",     "00sig00");

	// define as a constant to speed up decryptions
	define("REPLACE_RC4", checkReplaceRC4());

	// ===== HELPER FUNCTIONS =====

	// check if we have to use our own RC4 implementation
	function checkReplaceRC4() {
		// with OpenSSL v3 we assume that we have to replace the RC4 algo
		$result = (OPENSSL_VERSION_NUMBER >= 0x30000000);

		if ($result) {
			// maybe someone has re-enabled the legacy support in OpenSSL v3
			$result = (false === openssl_encrypt("test", "rc4", "test", OPENSSL_RAW_DATA, "", $tag, "", 0));
		}

		return $result;
	}

	// concatenate path pieces fixing leading and trailing slashes
	function concatPath($directory, $file) {
		if (0 < strlen($directory)) {
			if ("/" !== $directory[strlen($directory)-1]) {
				$directory .= "/";
			}
		}

		if (0 < strlen($file)) {
			if ("/" === $file[0]) {
				$file = substr($file, 1);
			}
		}

		return $directory.$file;
	}

	// print messages only if the debug mode is active
	function debug($string) {
		if (DEBUG_MODE) {
			println("DEBUG: $string");
		}
	}

	// decrypted JSON-wrapped blobs
	function decryptJson($file) {
		$result = false;

		$parts     = explode("|", $file);
		$partCount = count($parts);

		if (($partCount >= 3) && ($partCount <= 4)) {
			// we only proceed if all strings are hexadecimal
			$proceed = true;
			foreach ($parts as $part) {
				$proceed = ($proceed && ctype_xdigit($part));
			}

			if ($proceed) {
				$ciphertext = hex2bin($parts[0]);
				$iv         = $parts[1];
				$secretkey  = SECRET;

				if ($partCount === 4) {
					$version = $parts[3];
					if (intval($version) >= 2) {
						$iv = hex2bin($iv);
					}
					if (intval($version) === 3) {
						$temp      = hash_hkdf("sha512", $secretkey);
						$secretkey = substr($temp, 0, 32);
					}
				}

				$secretkey  = hash_pbkdf2("sha1", $secretkey, "phpseclib", 1000, 16, true);
				$json       = openssl_decrypt($ciphertext, "aes-128-cbc", $secretkey, OPENSSL_RAW_DATA, $iv);
				if (false !== $json) {
					$json = json_decode($json, true);
					if (is_array($json)) {
						if (DEBUG_MODE_VERBOSE) {
							debug("json = ".var_export($json, true));
						}

						if (array_key_exists("key", $json)) {
							$result = base64_decode($json["key"]);
						}
					}
				} else {
					debug("json could not be decrypted: ".openssl_error_string());
				}
			}
		}

		return $result;
	}

	// parse a private key file and try to decrypt it
	function decryptPrivateKey($file, $password, $keyid) {
		$result = false;

		$header = parseHeader($file, SUPPORT_MISSING_HEADERS);

		// strip header to parse meta data
		$meta = $file;
		if (substr($meta, 0, strlen(HEADER_BEGIN)) === HEADER_BEGIN) {
			$meta = substr($meta, strpos($meta, HEADER_END)+strlen(HEADER_END));
		}
		$meta = parseMeta($meta);

		if (is_array($header) && is_array($meta)) {
			if (array_key_exists(HEADER_CIPHER, $header) &&
			    array_key_exists(HEADER_ENCODING, $header) &&
			    array_key_exists(HEADER_KEYFORMAT, $header) &&
			    array_key_exists(META_ENCRYPTED, $meta) &&
			    array_key_exists(META_IV, $meta)) {
				// set default secret key
				$secretkey = $password;

				// check if we need to generate the password hash,
				// if so then generate it via PBKDF2 that matches the
				// required key length for the given cipher
				if (HEADER_KEYFORMAT_HASH === $header[HEADER_KEYFORMAT]) {
					// required before PHP 8.2
					$salt = hash("sha256", $keyid.INSTANCEID.SECRET, true);
					if ((false !== $salt) && array_key_exists(strtoupper($header[HEADER_CIPHER]), CIPHER_SUPPORT)) {
						$secretkey = hash_pbkdf2("sha256", $secretkey, $salt, 100000, CIPHER_SUPPORT[strtoupper($header[HEADER_CIPHER])], true);
					}

					// usable starting with PHP 8.2
					// if ((false !== $salt) && (false !== openssl_cipher_key_length($header[HEADER_CIPHER]))) {
					// 	$secretkey = hash_pbkdf2("sha256", $secretkey, $salt, 100000, openssl_cipher_key_length($header[HEADER_CIPHER]), true);
					// }
				}

				$privatekey = openssl_decrypt($meta[META_ENCRYPTED], $header[HEADER_CIPHER], $secretkey, (HEADER_ENCODING_BINARY === $header[HEADER_ENCODING]) ? OPENSSL_RAW_DATA : 0, $meta[META_IV]);
				if (false !== $privatekey) {
					$res = openssl_pkey_get_private($privatekey);
					if (is_resource($res) || ($res instanceof OpenSSLAsymmetricKey)) {
						$sslInfo = openssl_pkey_get_details($res);
						if (array_key_exists("key", $sslInfo)) {
							$result = $privatekey;
						}
					}
				} else {
					debug("privatekey could not be decrypted: ".openssl_error_string());
				}
			}
		}

		return $result;
	}

	// try to decrypt all available private keys
	function decryptPrivateKeys() {
		$result = [];

		// try to read generic keys
		$filelist = recursiveScandir(concatPath(DATADIRECTORY, "files_encryption/OC_DEFAULT_MODULE/"), true);
		foreach ($filelist as $filename) {
			if (is_file($filename)) {
				$keyname  = null;
				$keyid    = null;
				$password = null;

				if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                     "files_encryption/OC_DEFAULT_MODULE/(?<keyname>master_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
					$keyname  = $matches["keyname"];
					$keyid    = $keyname;
					$password = SECRET;
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "files_encryption/OC_DEFAULT_MODULE/(?<keyname>pubShare_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
					$keyname  = $matches["keyname"];
					$keyid    = "";
					$password = "";
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "files_encryption/OC_DEFAULT_MODULE/(?<keyname>recovery(Key)?_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
					$keyname  = $matches["keyname"];
					$keyid    = "";
					$password = RECOVERY_PASSWORD;
				}

				if (null !== $keyname) {
					$file = file_get_contents_try_json($filename);
					if (false !== $file) {
						$privatekey = decryptPrivateKey($file, $password, $keyid);
						if (false !== $privatekey) {
							$result[$keyname] = $privatekey;

							debug("loaded private key for $keyname");
						}
					}
				}
			}
		}

		// try to read user keys
		$filelist = recursiveScandir(DATADIRECTORY, false);
		foreach ($filelist as $filename) {
			if (is_dir($filename)) {
				if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
                                                     "(?<keyname>[0-9A-Za-z\.\-\_\@]+)$@", $filename, $matches)) {
					$keyname  = $matches["keyname"];
					$filename = concatPath(DATADIRECTORY, $keyname."/files_encryption/OC_DEFAULT_MODULE/".$keyname.".privateKey");
					$password = null;

					// try to retrieve the user password
					if (array_key_exists(strtolower($keyname), USER_PASSWORDS)) {
						$password = USER_PASSWORDS[strtolower($keyname)];
					}

					if (is_file($filename) && (null !== $password)) {
						$file = file_get_contents_try_json($filename);
						if (false !== $file) {
							$privatekey = decryptPrivateKey($file, $password, $keyname);
							if (false !== $privatekey) {
								$result[$keyname] = $privatekey;

								debug("loaded private key for $keyname");
							}
						}
					}
				}
			}
		}

		return $result;
	}

	// read a file and automagically try to decrypt it in case it is a JSON-wrapped blob
	function file_get_contents_try_json($filename) {
		$result = file_get_contents($filename);

		if (false !== $result) {
			$tmp = decryptJson($result);
			if (false !== $tmp) {
				$result = $tmp;
			}
		}

		return $result;
	}

	// try to parse the file header
	function parseHeader($file, $supportMissingHeaders) {
		$result = [];

		if (substr($file, 0, strlen(HEADER_BEGIN)) === HEADER_BEGIN) {
			// prepare default values
			$result[HEADER_CIPHER]               = HEADER_CIPHER_LEGACY;
			$result[HEADER_ENCODING]             = HEADER_ENCODING_BASE64;
			$result[HEADER_KEYFORMAT]            = HEADER_KEYFORMAT_PASSWORD;
			$result[HEADER_OC_ENCRYPTION_MODULE] = HEADER_OC_ENCRYPTION_MODULE_DEFAULT;
			$result[HEADER_SIGNED]               = HEADER_SIGNED_FALSE;

			$endAt  = strpos($file, HEADER_END);
			$header = substr($file, 0, $endAt+strlen(HEADER_END));

			// +1 not to start with an ':' which would result in empty element at the beginning
			$exploded = explode(":", substr($header, strlen(HEADER_BEGIN)+1));
			$element  = array_shift($exploded);
			while ($element !== HEADER_END) {
				$result[$element] = array_shift($exploded);
				$element          = array_shift($exploded);
			}
		} elseif ($supportMissingHeaders) {
			// prepare default values
			$result[HEADER_CIPHER]               = HEADER_CIPHER_LEGACY;
			$result[HEADER_ENCODING]             = HEADER_ENCODING_BASE64;
			$result[HEADER_KEYFORMAT]            = HEADER_KEYFORMAT_PASSWORD;
			$result[HEADER_OC_ENCRYPTION_MODULE] = HEADER_OC_ENCRYPTION_MODULE_DEFAULT;
			$result[HEADER_SIGNED]               = HEADER_SIGNED_FALSE;

			debug("key is using legacy format, setting cipher and key format");
		}

		if (DEBUG_MODE_VERBOSE) {
			debug("header = ".var_export($result, true));
		}

		return $result;
	}

	// try to parse the block
	function parseMeta($file) {
		$result = [];

		// check if there is a signature in the block
		if (false !== strpos(substr($file, -93), META_SIGNATURE_TAG)) {
			// remove the long padding from the block
			if (META_PADDING_TAG_LONG === substr($file, -3)) {
				$file = substr($file, 0, -3);
			}
			$meta = substr($file, -93);

			$result[META_ENCRYPTED] = substr($file, 0, -93);
			$result[META_IV]        = substr($meta, strlen(META_IV_TAG), 16);
			$result[META_SIGNATURE] = substr($meta, 22+strlen(META_SIGNATURE_TAG));
		} else {
			// remove the short padding from the block
			if (META_PADDING_TAG_SHORT === substr($file, -2)) {
				$file = substr($file, 0, -2);
			}
			$meta = substr($file, -22);

			$result[META_ENCRYPTED] = substr($file, 0, -22);
			$result[META_IV]        = substr($meta, -16);
			$result[META_SIGNATURE] = false;
		}

		if (DEBUG_MODE_VERBOSE) {
			// prepare array for debugging
			$debug_result = [META_ENCRYPTED => shortenString(bin2hex($result[META_ENCRYPTED]), 131, "...")." (".strlen($result[META_ENCRYPTED])." bytes)",
			                 META_IV        => bin2hex($result[META_IV]),
			                 META_SIGNATURE => $result[META_SIGNATURE]];
			debug("meta = ".var_export($debug_result, true));
		}

		return $result;
	}

	// print messages with a line break
	function println($string) {
		print($string.PHP_EOL);
	}

	// hands-down implementation of RC4
	function rc4($data, $secret) {
		$result = false;

		// initialize $state
		$state = [];
		for ($i = 0x00; $i <= 0xFF; $i++) {
			$state[$i] = $i;
		}

		// mix $secret into $state
		$indexA = 0x00;
		$indexB = 0x00;
		for ($i = 0x00; $i <= 0xFF; $i++) {
			$indexB = ($indexB + ord($secret[$indexA]) + $state[$i]) % 0x100;

			$tmp            = $state[$i];
			$state[$i]      = $state[$indexB];
			$state[$indexB] = $tmp;

			$indexA = ($indexA + 0x01) % strlen($secret);
		}

		// decrypt $data with $state
		$indexA = 0x00;
		$indexB = 0x00;
		$result = "";
		for ($i = 0x00; $i < strlen($data); $i++) {
			$indexA = ($indexA + 0x01) % 0x100;
			$indexB = ($state[$indexA] + $indexB) % 0x100;

			$tmp            = $state[$indexA];
			$state[$indexA] = $state[$indexB];
			$state[$indexB] = $tmp;

			$result .= chr(ord($data[$i]) ^ $state[($state[$indexA] + $state[$indexB]) % 0x100]);
		}

		return $result;
	}

	// scan a folder and optionally scan it recursively
	function recursiveScandir($path = "", $recursive = true) {
		$result = [];

		if ("" === $path) {
			$path = DATADIRECTORY;
		}

		$content = scandir($path);
		foreach ($content as $content_item) {
			if (("." !== $content_item) && (".." !== $content_item)) {
				if (is_file(concatPath($path, $content_item))) {
					$result[] = concatPath($path, $content_item);
				} elseif (is_dir(concatPath($path, $content_item))) {
					if ($recursive) {
						$result = array_merge($result, recursiveScandir(concatPath($path, $content_item)));
					} else {
						$result[] = concatPath($path, $content_item);
					}
				}
			}
		}

		return $result;
	}

	// shorten a string with a filler
	function shortenString($string, $length, $filler = "...") {
		$result = $string;

		// check if it makes sense to shorten the string
		if ((strlen($result) > $length) && (strlen($filler) < $length)) {
			$result = substr_replace($result, $filler, ceil($length - strlen($filler)) / 2, -floor(($length - strlen($filler)) / 2));
		}

		return $result;
	}

	// try to do an RC4 openssl_open() but fall back to our custom implementation if needed
	function wrapped_openssl_open($data, &$output, $encrypted_key, $private_key, $cipher_algo, $iv = null) {
		$result = false;

		if ((0 === strcasecmp($cipher_algo, "rc4")) && REPLACE_RC4) {
			if (openssl_private_decrypt($encrypted_key, $intermediate, $private_key, OPENSSL_PKCS1_PADDING)) {
				$output = rc4($data, $intermediate);
				$result = (false !== $output);
				if (!$result) {
					debug("rc4() failed");
				}
			} else {
				debug("openssl_private_decrypt() failed: ".openssl_error_string());
			}
		} else {
			$result = openssl_open($data, $output, $encrypted_key, $private_key, $cipher_algo, $iv);
			if (!$result) {
				debug("openssl_open() failed: ".openssl_error_string());
			}
		}

		return $result;
	}

	// ===== MAIN FUNCTIONS =====

	// check if a file has a header and if not copy it to the target
	function copyFile($filename, $target) {
		$result = false;

		// try to set file times later on
		$fileatime = fileatime($filename);
		$filemtime = filemtime($filename);

		// we will not try to copy encrypted files
		$isplain = false;

		$sourcefile = fopen($filename, "r");
		try {
			$buffer = "";
			$tmp    = "";
			do {
				$tmp = fread($sourcefile, BLOCKSIZE);
				if (false !== $tmp) {
					$buffer .= $tmp;
				}
			} while ((BLOCKSIZE > strlen($buffer)) && (!feof($sourcefile)));

			// check if the source file does not start with a header
			$header  = parseHeader(substr($buffer, 0, BLOCKSIZE), false);
			$isplain = (0 === count($header));
		} finally {
			fclose($sourcefile);
		}

		if ($isplain) {
			$result = copy($filename, $target);

			// try to set file times
			if ($result && (false !== $filemtime)) {
				// fix access time if necessary
				if (false === $fileatime) {
					$fileatime = time();
				}

				touch($target, $filemtime, $fileatime);
			}
		}

		return $result;
	}

	// decrypt a single file block
	function decryptBlock($header, $block, $secretkey) {
		$result = false;

		$meta = parseMeta($block);

		if (is_array($header) && is_array($meta)) {
			if (array_key_exists(HEADER_CIPHER, $header) &&
			    array_key_exists(HEADER_ENCODING, $header) &&
			    array_key_exists(META_ENCRYPTED, $meta) &&
			    array_key_exists(META_IV, $meta)) {
				$output = openssl_decrypt($meta[META_ENCRYPTED], $header[HEADER_CIPHER], $secretkey, (HEADER_ENCODING_BINARY === $header[HEADER_ENCODING]) ? OPENSSL_RAW_DATA : 0, $meta[META_IV]);
				if (false !== $output) {
					$result = $output;
				} else {
					debug("block could not be decrypted: ".openssl_error_string());
				}
			}
		}

		return $result;
	}

	// try to decrypt a file
	function decryptFile($filename, $secretkey, $target) {
		$result = false;

		// try to set file times later on
		$fileatime = fileatime($filename);
		$filemtime = filemtime($filename);

		$sourcefile = fopen($filename, "r");
		$targetfile = fopen($target,   "w");
		try {
			$result = true;

			$block  = "";
			$buffer = "";
			$first  = true;
			$header = null;
			$plain  = "";
			$tmp    = "";
			do {
				$tmp = fread($sourcefile, BLOCKSIZE);
				if (false !== $tmp) {
					$buffer .= $tmp;

					while (BLOCKSIZE <= strlen($buffer)) {
						$block  = substr($buffer, 0, BLOCKSIZE);
						$buffer = substr($buffer, BLOCKSIZE);

						// the first block contains the header
						if ($first) {
							$first  = false;
							$header = parseHeader($block, SUPPORT_MISSING_HEADERS);
						} else {
							$plain = decryptBlock($header, $block, $secretkey);
							if (false !== $plain) {
								// write fails when fewer bytes than string length are written
								$result = $result && (strlen($plain) === fwrite($targetfile, $plain));
							} else {
								// decryption failed
								$result = false;
							}
						}
					}
				}
			} while (!feof($sourcefile));

			// decrypt trailing blocks
			while (0 < strlen($buffer)) {
				$block  = substr($buffer, 0, BLOCKSIZE);
				$buffer = substr($buffer, BLOCKSIZE);

				// the file only has 1 block, parsing the header before decryption
				if ($first) {
					$first  = false;
					$header = parseHeader($block, SUPPORT_MISSING_HEADERS);
				}

				$plain = decryptBlock($header, $block, $secretkey);
				if (false !== $plain) {
					// write fails when fewer bytes than string length are written
					$result = $result && (strlen($plain) === fwrite($targetfile, $plain));
				} else {
					// decryption failed
					$result = false;
				}
			}
		} finally {
			fclose($sourcefile);
			fclose($targetfile);
		}

		// try to set file times
		if ($result && (false !== $filemtime)) {
			// fix access time if necessary
			if (false === $fileatime) {
				$fileatime = time();
			}

			touch($target, $filemtime, $fileatime);
		}

		return $result;
	}

	// iterate over the file lists and try to decrypt the files
	function decryptFiles($targetdir, $sourcepaths = null) {
		$result = 0;

		$privatekeys = decryptPrivateKeys();
		if (0 < count($privatekeys)) {
			// collect all file sources
			$sources = [];

			// set sourcepaths to all folders in the data directory
			if ((null === $sourcepaths) || (0 === count($sourcepaths))) {
				$sourcepaths = recursiveScandir(DATADIRECTORY, false);
			}

			// add the sourcepaths entries as sources
			foreach ($sourcepaths as $path) {
				// only handle non-empty paths
				if (0 < strlen($path)) {
					// make sure that the given path is a full path
					if ("/" !== $path[0]) {
						$path = concatPath(DATADIRECTORY, $path);
					}

					// only add path to source if it exists
					if (is_file($path) || is_dir($path)) {
						$sources["\0".count($sources)] = $path;
					}
				}
			}

			// add external storage folders as sources
			foreach (EXTERNAL_STORAGES as $key => $value) {
				if (is_dir($value)) {
					$sources[$key] = $value;
				} else {
					println("WARNING: EXTERNAL STORAGE $value DOES NOT EXIST");
				}
			}

			foreach ($sources as $source => $path) {
				// get the filelist in-time
				$filelist = null;
				if (is_file($path)) {
					$filelist = [$path];
				} else {
					$filelist = recursiveScandir($path);
				}

				foreach ($filelist as $filename) {
					if (is_file($filename)) {
						debug("filename = $filename");

						// generate target filename
						$target = null;
						if ("\0" === $source[0]) {
							$target = concatPath($targetdir, substr($filename, strlen(DATADIRECTORY)));
						} else {
							// do we handle a user-specific external storage
							if (false === strpos($source, "/")) {
								$target = concatPath(concatPath($targetdir, EXTERNAL_PREFIX.$source),
								                     substr($filename, strlen($path)));
							} else {
								$target = concatPath(concatPath(concatPath($targetdir, substr($source, 0, strpos($source, "/"))),
								                                EXTERNAL_PREFIX.substr($source, strpos($source, "/")+1)),
								                     substr($filename, strlen($path)));
							}
						}
						debug("target = $target");

						// only proceed if the target does not already exist
						if (!is_file($target)) {
							$success = false;

							$datafilename = null;
							$istrashbin   = false;
							$username     = null;

							// do we handle the data directory or an external storage
							if ("\0" === $source[0]) {
								if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
								                     "(?<username>[^/]+)/files/(?<datafilename>.+)$@", $filename, $matches)) {
									$datafilename = $matches["datafilename"];
									$istrashbin   = false;
									$username     = $matches["username"];
								} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
								                           "(?<username>[^/]+)/files_trashbin/files/(?<datafilename>.+)$@", $filename, $matches)) {
									$datafilename = $matches["datafilename"];
									$istrashbin   = true;
									$username     = $matches["username"];
								} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
								                           "(?<username>[^/]+)/files_versions/(?<datafilename>.+)\.v[0-9]+$@", $filename, $matches)) {
									$datafilename = $matches["datafilename"];
									$istrashbin   = false;
									$username     = $matches["username"];
								} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
								                           "(?<username>[^/]+)/files_trashbin/versions/(?<datafilename>.+)\.v[0-9]+(?<deletetime>\.d[0-9]+)$@", $filename, $matches)) {
									$datafilename = $matches["datafilename"].$matches["deletetime"];
									$istrashbin   = true;
									$username     = $matches["username"];
								} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
								                           "(?<username>[^/]+)/files_trashbin/versions/(?<datafilename>.+)\.v[0-9]+$@", $filename, $matches)) {
									$datafilename = $matches["datafilename"];
									$istrashbin   = true;
									$username     = $matches["username"];
								}
							} else {
								// do we handle a user-specific external storage
								if (false === strpos($source, "/")) {
									$datafilename = concatPath($source,
									                           substr($filename, strlen($path)));
									$istrashbin   = false;
									$username     = "";
								} else {
									$datafilename = concatPath(substr($source, strpos($source, "/")+1),
									                           substr($filename, strlen($path)));
									$istrashbin   = false;
									$username     = substr($source, 0, strpos($source, "/"));
								}
							}

							// do we know how to handle this specific file path
							if (null !== $datafilename) {
								debug("datafilename = $datafilename");
								debug("istrashbin = ".($istrashbin ? "true" : "false"));
								debug("username = $username");

								$isencrypted = false;
								$secretkey   = null;
								$subfolder   = null;

								if ($istrashbin) {
									$subfolder = "files_trashbin/files";
								} else {
									$subfolder = "files";
								}

								$filekeyname = concatPath(DATADIRECTORY,
								                          $username."/files_encryption/keys/".$subfolder."/".$datafilename."/OC_DEFAULT_MODULE/fileKey");
								if (is_file($filekeyname)) {
									$isencrypted = true;

									debug("filekeyname = $filekeyname");
									debug("isencrypted = ".($isencrypted ? "true" : "false"));

									foreach ($privatekeys as $key => $value) {
										$sharekeyname = concatPath(DATADIRECTORY,
										                           $username."/files_encryption/keys/".$subfolder."/".$datafilename."/OC_DEFAULT_MODULE/".$key.".shareKey");
										if (is_file($sharekeyname)) {
											debug("sharekeyname = $sharekeyname");

											$filekey  = file_get_contents_try_json($filekeyname);
											$sharekey = file_get_contents_try_json($sharekeyname);
											if ((false !== $filekey) && (false !== $sharekey)) {
												if (wrapped_openssl_open($filekey, $tmpkey, $sharekey, $privatekeys[$key], "rc4")) {
													$secretkey = $tmpkey;
													break;
												} else {
													debug("secretkey could not be decrypted");
												}
											} else {
												debug("filekey or sharekey could not be read from file");
											}
										}
									}
								}
								debug("secretkey = ".((null !== $secretkey) ? "decrypted" : "unavailable"));

								// try to recursively create the target subfolder
								if (!is_dir(dirname($target))) {
									mkdir(dirname($target), 0777, true);
								}

								// if the file provides all relevant key material then we try to decrypt it
								if ($isencrypted) {
									if (null !== $secretkey) {
										debug("trying to decrypt file...");

										$success = decryptFile($filename, $secretkey, $target);
									} else {
										debug("cannot decrypt this file...");
									}
								}

								// if the file does not provide all relevant key material or if the file
								// could not be decrypted (maybe due to missing headers) we try to copy it,
								// but we copy it only if it does not contain an encryption header and only
								// if the decryption hasn't created a file already
								if ((!$success) && ((!is_file($target)) || (0 >= filesize($target)))) {
									debug("trying to copy file...");

									$success = copyFile($filename, $target);
								}
								debug("success = ".($success ? "true" : "false"));

								if ($success) {
									println("DONE: $filename");
								} else {
									// we failed but created a file,
									// discard the broken file
									if (is_file($target)) {
										unlink($target);
									}

									println("ERROR: $filename FAILED");
									$result = 4;
								}
							} else {
								debug("skipping this file...");
							}
						} else {
							println("SKIP: $target ALREADY EXISTS");
						}
					}
				}
			}
		} else {
			println("ERROR: COULD NOT DECRYPT ANY PRIVATE KEY");
			$result = 3;
		}

		return $result;
	}

	// ===== MAIN ENTRYPOINT =====

	// handle the parameters
	function main($arguments) {
		$result = 0;

		debug("debug mode enabled");

		// we want to work with an empty stat cache
		clearstatcache(true);

		if (is_dir(DATADIRECTORY)) {
			$targetdir = null;
			if (2 <= count($arguments)) {
				$targetdir = $arguments[1];
			}

			$sourcepaths = [];
			if (3 <= count($arguments)) {
				$sourcepaths = array_slice($arguments, 2);
			}

			if ((null !== $targetdir) && is_dir($targetdir)) {
				$result = decryptFiles($targetdir, $sourcepaths);
			} else {
				println("ERROR: TARGETDIR NOT GIVEN OR DOES NOT EXIST");
				$result = 2;
			}
		} else {
			println("ERROR: DATADIRECTORY DOES NOT EXIST");
			$result = 1;
		}

		debug("exiting");

		return $result;
	}

	// main entrypoint
	exit(main($argv));


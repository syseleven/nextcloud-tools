<?php

	# encrypt-file.php
	#
	# Copyright (c) 2019, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./encrypt-file.php <filename> <filekey> <version>
	#
	# <filekey> has to be hexadecimally encoded and the payload has to be 32 bytes long,
	# can be created with `openssl rand -hex 32`
	#
	# <version> has to be an integer that denotes the file version

	// static definitions
	define("BLOCKSIZE", 6072);
	define("NONCESIZE", 16);

	function createSignature($encrypted, $passphrase) {
		$result = false;

		$passphrase = hash("sha512", $passphrase."a", true);
		if (false !== $passphrase) {
			$result = hash_hmac("sha256", $encrypted, $passphrase);
		}

		return $result;
	}

	function getFileKey($argv) {
		$result = null;

		if (3 <= count($argv)) {
			if ((0 < strlen($argv[2])) && (64 === strlen($argv[2]))) {
				$result = hex2bin($argv[2]);

				if (false === $result) {
					$result = null;
				}
			}
		}

		return $result;
	}

	function getFilename($argv) {
		$result = null;

		if (2 <= count($argv)) {
			if (is_file($argv[1])) {
				$result = $argv[1];
			}
		}

		return $result;
	}

	function getVersion($argv) {
		$result = null;

		if (4 <= count($argv)) {
			if (is_numeric($argv[3])) {
				$result = intval($argv[3]);
			}
		}

		return $result;
	}

	function main($argv) {
		$result = 1;

		$filename = getFilename($argv);
		$filekey  = getFileKey($argv);
		$version  = getVersion($argv);
		if ((null !== $filename) && (null !== $filekey) && (null !== $version)) {
			$file = file_get_contents($filename);
			if (false !== $file) {
				$result = 0;

				# print the header
				print("HBEGIN:oc_encryption_module:OC_DEFAULT_MODULE:cipher:AES-256-CTR:signed:true:HEND");
				print(str_repeat("-", 8111));

				$position = 0;
				while (BLOCKSIZE*$position < strlen($file)) {
					$block = substr($file, BLOCKSIZE*$position, BLOCKSIZE);
					$nonce = openssl_random_pseudo_bytes(NONCESIZE, $crypto_strong);

					if ((false !== $nonce) && $crypto_strong) {
						$encblock = openssl_encrypt($block, "AES-256-CTR", $filekey, 0, $nonce);
						if (false !== $encblock) {
							$end = "";
							if (BLOCKSIZE*($position+1) >= strlen($file)) {
								$end = "end";
							}

							$macblock = createSignature($encblock, $filekey.$version.$position.$end);
							if (false !== $macblock) {
								# print the block
								print($encblock);
								print("00iv00");
								print($nonce);
								print("00sig00");
								print($macblock);
								print("xxx");
							} else {
								$result = 4;
							}
						} else {
							$result = 3;
						}
					} else {
						$result = 2;
					}

					$position++;
				}

				$result = 0;
			}
		}

		return $result;
	}

	exit(main($argv));


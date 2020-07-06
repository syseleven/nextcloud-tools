<?php

	# encrypt-envelopekey.php
	#
	# Copyright (c) 2019-2020, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./encrypt-envelopekey.php <envelopekey> <publickey filename>
	#
	# <envelopekey> has to be hexadecimally encoded and the payload has to be 16 bytes long,
	# can be created with `openssl rand -hex 16`

	function getEnvelopeKey($argv) {
		$result = null;

		if (2 <= count($argv)) {
			if ((0 < strlen($argv[1])) && (32 === strlen($argv[1]))) {
				$result = hex2bin($argv[1]);

				if (false === $result) {
					$result = null;
				}
			}
		}

		return $result;
	}

	function getPublicKeyFilename($argv) {
		$result = null;

		if (3 <= count($argv)) {
			if (is_file($argv[2])) {
				$result = $argv[2];
			}
		}

		return $result;
	}

	function main($argv) {
		$result = 1;

		$envelopekey       = getEnvelopeKey($argv);
		$publickeyfilename = getPublicKeyFilename($argv);
		if ((null !== $envelopekey) && (null !== $publickeyfilename)) {
			$publickeypem = file_get_contents($publickeyfilename);
			if (false !== $publickeypem) {
				$publickey = openssl_pkey_get_public($publickeypem);
				if (false !== $publickey) {
					try {
						# openssl_seal() uses PKCS#1 v1.5 padding
						if (openssl_public_encrypt($envelopekey, $output, $publickey)) {
							print($output);

							$result = 0;
						}
					} finally {
						openssl_pkey_free($publickey);
					}
				}
			}
		}

		return $result;
	}

	exit(main($argv));


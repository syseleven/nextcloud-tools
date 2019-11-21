<?php

	# encrypt-filekey.php
	#
	# Copyright (c) 2019, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./encrypt-filekey.php <filekey> <envelopekey>
	#
	# <filekey> has to be hexadecimally encoded and the payload has to be 32 bytes long,
	# can be created with `openssl rand -hex 32`
	#
	# <envelopekey> has to be hexadecimally encoded and the payload has to be 16 bytes long,
	# can be created with `openssl rand -hex 16`

	function getFileKey($argv) {
		$result = null;

		if (2 <= count($argv)) {
			if ((0 < strlen($argv[1])) && (64 === strlen($argv[1]))) {
				$result = hex2bin($argv[1]);

				if (false === $result) {
					$result = null;
				}
			}
		}

		return $result;
	}

	function getEnvelopeKey($argv) {
		$result = null;

		if (3 <= count($argv)) {
			if ((0 < strlen($argv[2])) && (32 === strlen($argv[2]))) {
				$result = hex2bin($argv[2]);

				if (false === $result) {
					$result = null;
				}
			}
		}

		return $result;
	}

	function main($argv) {
		$result = 1;

		$filekey     = getFileKey($argv);
		$envelopekey = getEnvelopeKey($argv);
		if ((null !== $filekey) && (null !== $envelopekey)) {
			$output = openssl_encrypt($filekey, "RC4", $envelopekey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

			if (false !== $output) {
				print($output);

				$result = 0;
			}
		}

		return $result;
	}

	exit(main($argv));


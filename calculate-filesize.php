<?php

	# calculate-filesize.php
	#
	# Copyright (c) 2019-2020, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./calculate-filesize.php <filename>

	// static definitions
	define("BLOCKSIZE",     8192);
	define("DEBUG_DEBUG",   2);
	define("DEBUG_DEFAULT", 0);
	define("DEBUG_INFO",    1);

	// nextcloud definitions - you can get these values from config/config.php
	define("DATADIRECTORY", "");

	// custom definitions
	define("DEBUGLEVEL", DEBUG_DEFAULT);

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

	function debug($text, $debuglevel = DEBUG_DEFAULT) {
		if (DEBUGLEVEL >= $debuglevel) {
			print("$text\n");
		}
	}

	function getFilename($argv) {
		$result = null;

		if (2 <= count($argv)) {
			$result = $argv[1];
			if (0 < strlen($result)) {
				if ("/" !== $result[0]) {
					$result = concatPath(DATADIRECTORY, $result);
				}
			}
		}

		return $result;
	}

	function getKeySize($cipher) {
		$result = false;

		$supportedCiphersAndKeySize = ["AES-256-CTR" => 32,
		                               "AES-128-CTR" => 16,
		                               "AES-256-CFB" => 32,
		                               "AES-128-CFB" => 16];

		if (array_key_exists($cipher, $supportedCiphersAndKeySize)) {
			$result = $supportedCiphersAndKeySize[$cipher];
		}

		return $result;
	}

	function hasPadding($padded, $hasSignature = false) {
		$result = false;

		if ($hasSignature) {
			$result = ("xxx" === substr($padded, -3));
		} else {
			$result = ("xx" === substr($padded, -2));
		}

		return $result;
	}	

	function hasSignature($file) {
		$meta = substr($file, -93);
		$pos  = strpos($meta, "00sig00");

		return ($pos !== false);
	}

	function removePadding($padded, $hasSignature = false) {
		$result = false;

		if ($hasSignature) {
			if ("xxx" === substr($padded, -3)) {
				$result = substr($padded, 0, -3);
			}
		} else {
			if ("xx" === substr($padded, -2)) {
				$result = substr($padded, 0, -2);
			}
		}

		return $result;
	}

	function splitMetaData($file) {
		if (hasSignature($file)) {
			$file      = removePadding($file, true);
			$meta      = substr($file, -93);
			$iv        = substr($meta, strlen("00iv00"), 16);
			$sig       = substr($meta, 22+strlen("00sig00"));
			$encrypted = substr($file, 0, -93);
		} else {
			$file      = removePadding($file);
			$meta      = substr($file, -22);
			$iv        = substr($meta, -16);
			$sig       = false;
			$encrypted = substr($file, 0, -22);
		}

		return ["encrypted" => $encrypted,
			"iv"        => $iv,
			"signature" => $sig];
	}

	function stripHeader($encrypted) {
		return substr($encrypted, strpos($encrypted, HEADER_END)+strlen(HEADER_END));
	}

	function calculateFilesize($file) {
		$result = true;

		$filesize = 0;
		$strlen   = strlen($file);
		for ($i = 0; $i < intval(ceil($strlen/BLOCKSIZE)); $i++) {
			$block = substr($file, $i*BLOCKSIZE, BLOCKSIZE);
			$temp  = false;

			if (0 === $i) {
				$temp = true;
			} else {
				$meta = splitMetaData($block);
				debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

				if (array_key_exists("encrypted", $meta)) {
					$blocksize = strlen(base64_decode($meta["encrypted"]));

					if (false !== $blocksize) {
						$filesize += $blocksize;

						$temp = true;
					}
				}
			}

			$result = ($result && $temp);
		}

                # print the file size
                if ($result) {
                        print(strval($filesize));
                }

		return $result;
	}

	function handleFile($filename) {
		$result = 1;

		if (!is_file($filename)) {
			debug("$filename: File is not a file.", DEBUG_DEFAULT);
		} else {
			$file = file_get_contents($filename);
			if (false === $file) {
				debug("$filename: File could not be read.", DEBUG_DEFAULT);
			} else {
				if (!calculateFilesize($file)) {
					debug("$filename: File size not calculated.", DEBUG_DEFAULT);
				} else {
					$result = 0;
				}
			}
		}

		return $result;
	}

	function main($argv) {
		$result = 1;

		$filename = getFilename($argv);
		if (null !== $filename) {
			debug("##################################################", DEBUG_DEBUG);
			debug("\$filename = ".var_export($filename, true), DEBUG_DEBUG);

			if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                     "(?<username>[^/]+)/files/(?<datafilename>.+)$@", $filename, $matches)) {
				$result = handleFile($filename);
			} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                           "(?<username>[^/]+)/files_trashbin/files/(?<datafilename>.+)$@", $filename, $matches)) {
				$result = handleFile($filename);
			} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                           "(?<username>[^/]+)/files_versions/(?<datafilename>.+)\.v[0-9]+$@", $filename, $matches)) {
				$result = handleFile($filename);
			} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                           "(?<username>[^/]+)/files_trashbin/versions/(?<datafilename>.+)\.v[0-9]+(?<deletetime>\.d[0-9]+)$@", $filename, $matches)) {
				$result = handleFile($filename);
			} else {
				debug("$filename: File has unknown filename format.", DEBUG_DEFAULT);
			}

			debug("##################################################", DEBUG_DEBUG);
		}

		return $result;
	}

	exit(main($argv));


<?php

	# strip-signature.php
	#
	# Copyright (c) 2019, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./strip-signature.php <filename>

	// static definitions
	define("BLOCKSIZE",     8192);
	define("DEBUG_DEBUG",   2);
	define("DEBUG_DEFAULT", 0);
	define("DEBUG_INFO",    1);
	define("HEADER_END",    "HEND");
	define("HEADER_START",  "HBEGIN");

	// nextcloud definitions - you can get these values from config/config.php
	define("DATADIRECTORY", "");

	// custom definitions
	define("DEBUGLEVEL",  DEBUG_DEFAULT);
	define("MAXFILESIZE", 2147483648);

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

	function parseHeader($file) {
		$result = [];

		if (substr($file, 0, strlen(HEADER_START)) === HEADER_START) {
			$endAt  = strpos($file, HEADER_END);
			$header = substr($file, 0, $endAt+strlen(HEADER_END));

			// +1 not to start with an ':' which would result in empty element at the beginning
			$exploded = explode(":", substr($header, strlen(HEADER_START)+1));
			$element  = array_shift($exploded);

			while ($element !== HEADER_END) {
				$result[$element] = array_shift($exploded);
				$element          = array_shift($exploded);
			}
		}

		return $result;
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

	function stripFile($file) {
		$result = true;

		$strlen = strlen($file);
		for ($i = 0; $i < intval(ceil($strlen/BLOCKSIZE)); $i++) {
			$block = substr($file, $i*BLOCKSIZE, BLOCKSIZE);
			$temp  = false;

			if (0 === $i) {
				$blockModified = "HBEGIN:oc_encryption_module:OC_DEFAULT_MODULE:cipher:AES-256-CFB:HEND".str_repeat("-", 8123);

				if (strlen($block) === strlen($blockModified)) {
					print($blockModified);

					$temp = true;
				}
			} else {
				$meta = splitMetaData($block);
				debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

				if (array_key_exists("encrypted", $meta) &&
				    array_key_exists("signature", $meta) &&
				    (false !== $meta["signature"])) {
					$blockModified = $meta["encrypted"].str_repeat("=", 72)."00iv00".$meta["iv"]."xx";

					if (strlen($block) === strlen($blockModified)) {
						print($blockModified);

						$temp = true;
					}
				}
			}

			$result = ($result && $temp);
		}

		return $result;
	}

	function handleFile($filename) {
		$result = 1;

		if (!is_file($filename)) {
			debug("$filename: File is not a file.", DEBUG_DEFAULT);
		} else {
			$filesize = filesize($filename);
			if (false === $filesize) {
				debug("$filename: File size could not be retrieved.", DEBUG_DEFAULT);
			} else {
				if (MAXFILESIZE < $filesize) {
					debug("$filename: File size exceeds max file size.", DEBUG_DEFAULT);
				} else {
					$file = file_get_contents($filename);
					if (false === $file) {
						debug("$filename: File could not be read.", DEBUG_DEFAULT);
					} else {
						if (!stripFile($file)) {
							debug("$filename: File signature could not be stripped.", DEBUG_DEFAULT);
						} else {
							$result = 0;
						}
					}
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


<?php

	# usage:
	# ======
	#
	# php ./decryptfile.php <filename>

	// static definitions
	define("BLOCKSIZE",     8192);
	define("DEBUG_DEBUG",   2);
	define("DEBUG_DEFAULT", 0);
	define("DEBUG_INFO",    1);
	define("HEADER_END",    "HEND");
	define("HEADER_START",  "HBEGIN");

	// nextcloud definitions - you can get these values from config/config.php
	define("DATADIRECTORY", "");
	define("INSTANCEID",    "");
	define("SECRET",        "");

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

	function decryptPrivateKey($file, $password, $keyid) {
		$result = false;

		$header = parseHeader($file);
		$meta   = splitMetaData($file);

		if (array_key_exists("cipher", $header) &&
		    array_key_exists("encrypted", $meta) &&
		    array_key_exists("iv", $meta)) {
			if (array_key_exists("keyFormat", $header) && ("hash" === $header["keyFormat"])) {
				$password = generatePasswordHash($password, $header["cipher"], $keyid);
			}

			$key = openssl_decrypt(stripHeader($meta["encrypted"]), $header["cipher"], $password, false, $meta["iv"]);
			if (false !== $key) {
				$res = openssl_pkey_get_private($key);
				if (is_resource($res)) {
					$sslInfo = openssl_pkey_get_details($res);
					if (array_key_exists("key", $sslInfo)) {
						$result = $key;
					}
				}
			}
		}

		return $result;
	}

	function generatePasswordHash($password, $cipher, $uid = "") {
		$result = false;

		$keySize = getKeySize($cipher);
		$salt    = hash("sha256", $uid.INSTANCEID.SECRET, true);
		if ((false !== $keySize) && (false !== $salt)) {
			$result = hash_pbkdf2("sha256", $password, $salt, 100000, $keySize, true);
		}

		return $result;
	}

	function getFilename($argv) {
		$result = null;

		if (1 < count($argv)) {
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

	function getMasterKeyId() {
		$result = false;

		$filelist = recursiveScandir(concatPath(DATADIRECTORY, "files_encryption/OC_DEFAULT_MODULE/"));
		foreach ($filelist as $filename) {
			if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                     "files_encryption/OC_DEFAULT_MODULE/(?<masterkeyid>master_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
				$result = $matches["masterkeyid"];

				break;
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

	function recursiveScandir($path = "") {
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
					$result = array_merge($result, recursiveScandir(concatPath($path, $content_item)));
				}
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

	function decryptFile($file, $filekey, $masterkey, $sharekey, $version = 0, $position = 0) {
		$result = false;

		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);
		debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

		$masterkeyid = getMasterKeyId();
		debug("\$masterkeyid = ".var_export($masterkeyid, true), DEBUG_DEBUG);

		if (false !== $masterkeyid) {
			$masterkeyModified = decryptPrivateKey($masterkey, SECRET, $masterkeyid);
			if (openssl_open($filekey, $filekeyModified, $sharekey, $masterkeyModified)) {
				$result = true;

				$strlen = strlen($file);
				for ($i = 0; $i < intval(ceil($strlen/BLOCKSIZE)); $i++) {
					$block = substr($file, $i*BLOCKSIZE, BLOCKSIZE);
					$temp  = false;

					if (0 === $i) {
						$header = parseHeader($block);
						debug("\$header = ".var_export($header, true), DEBUG_DEBUG);

						$temp = true;
					} else {
						$meta = splitMetaData($block);
						debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

						if (array_key_exists("cipher", $header) &&
						    array_key_exists("encrypted", $meta) &&
						    array_key_exists("iv", $meta)) {
							$output = openssl_decrypt($meta["encrypted"], $header["cipher"], $filekeyModified, false, $meta["iv"]);
							if (false !== $output) {
								print($output);

								$temp = true;
							}
						}
					}

					$result = ($result && $temp);
				}
			}
		}

		return $result;
	}

	function handleFile($filename, $username, $datafilename, $istrashbin = false) {
		$result = 1;

		$masterkeyid = getMasterKeyId();
		if (false === $masterkeyid) {
			debug("$filename: Master key ID could not be retrieved.", DEBUG_DEFAULT);
		} else {
			$masterkeyname = concatPath(DATADIRECTORY,
			                            "files_encryption/OC_DEFAULT_MODULE/".$masterkeyid.".privateKey");

			if ($istrashbin) {
				$filekeyname  = concatPath(DATADIRECTORY,
					                   $username."/files_encryption/keys/files_trashbin/files/".$datafilename."/OC_DEFAULT_MODULE/fileKey");
				$sharekeyname = concatPath(DATADIRECTORY,
				                           $username."/files_encryption/keys/files_trashbin/files/".$datafilename."/OC_DEFAULT_MODULE/".$masterkeyid.".shareKey");
			} else {
				$filekeyname  = concatPath(DATADIRECTORY,
				                           $username."/files_encryption/keys/files/".$datafilename."/OC_DEFAULT_MODULE/fileKey");
				$sharekeyname = concatPath(DATADIRECTORY,
				                           $username."/files_encryption/keys/files/".$datafilename."/OC_DEFAULT_MODULE/".$masterkeyid.".shareKey");
			}

			if (!is_file($filename)) {
				debug("$filename: File is not a file.", DEBUG_DEFAULT);
			} else {
				if (!is_file($masterkeyname)) {
					debug("$filename: Masterkey is not a file.", DEBUG_DEFAULT);
				} else {
					if (!is_file($filekeyname)) {
						debug("$filename: Filekey is not a file.", DEBUG_DEFAULT);
					} else {
						if (!is_file($sharekeyname)) {
							debug("$filename: Sharekey is not a file.", DEBUG_DEFAULT);
						} else {
							$file = file_get_contents($filename);
							if (false === $file) {
								debug("$filename: File could not be read.", DEBUG_DEFAULT);
							} else {
								$masterkey = file_get_contents($masterkeyname);
								if (false === $masterkey) {
									debug("$filename: Masterkey could not be read.", DEBUG_DEFAULT);
								} else {
									$filekey = file_get_contents($filekeyname);
									if (false === $filekey) {
										debug("$filename: Filekey could not be read.", DEBUG_DEFAULT);
									} else {
										$sharekey = file_get_contents($sharekeyname);
										if (false === $sharekey) {
											debug("$filename: Sharekey could not be read.", DEBUG_DEFAULT);
										} else {
											if (!decryptFile($file, $filekey, $masterkey, $sharekey)) {
												debug("$filename: File not decrypted.", DEBUG_DEFAULT);
											} else {
												$result = 0;
											}
										}
									}
								}
							}
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
				$result = handleFile($filename, $matches["username"], $matches["datafilename"], false);
			} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                           "(?<username>[^/]+)/files_trashbin/files/(?<datafilename>.+)$@", $filename, $matches)) {
				$result = handleFile($filename, $matches["username"], $matches["datafilename"], true);
			} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                           "(?<username>[^/]+)/files_versions/(?<datafilename>.+)\.v[0-9]+$@", $filename, $matches)) {
				$result = handleFile($filename, $matches["username"], $matches["datafilename"], false);
			} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                           "(?<username>[^/]+)/files_trashbin/versions/(?<datafilename>.+)\.v[0-9]+(?<deletetime>\.d[0-9]+)$@", $filename, $matches)) {
				$result = handleFile($filename, $matches["username"], $matches["datafilename"].$matches["deletetime"], true);
			} else {
				debug("$filename: File has unknown filename format.", DEBUG_DEFAULT);
			}

			debug("##################################################", DEBUG_DEBUG);
		}

		return $result;
	}

	exit(main($argv));


<?php

	# usage:
	# ======
	#
	# php ./checksig.php [<filename>*]

	# preparation:
	# ============
	#
	# sudo -u <dbuser> psql -d <dbname>
	#
	#
	# \COPY (SELECT storage, path, encrypted FROM oc_filecache) TO '/tmp/filecache.csv' WITH CSV DELIMITER ',';
	# \COPY (SELECT numeric_id, id FROM oc_storages) TO '/tmp/storages.csv' WITH CSV DELIMITER ',';
	# \q
	#
	#
	# /tmp/filecache.csv must have this format:
	#
	# <storage>,<path>,<encrypted>
	# <storage>,<path>,<encrypted>
	# <storage>,<path>,<encrypted>
	# ...
	# <storage>,<path>,<encrypted>
	#
	#
	# /tmp/storages.csv must have this format:
	#
	# <numeric_id>,<id>
	# <numeric_id>,<id>
	# <numeric_id>,<id>
	# ...
	# <numeric_id>,<id>

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

	// static definitions
	define("DEBUGLEVEL",    DEBUG_DEFAULT);
	define("FILECACHE",     "/tmp/filecache.csv");
	define("FIXSIGNATURES", false); // CAUTION: setting this to TRUE may break your files
	define("STORAGES",      "/tmp/storages.csv");

	function checkSignature($signature, $expectedSignature) {
		return hash_equals($signature, $expectedSignature);
	}

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

	function createSignature($encrypted, $passphrase) {
		$result = false;

		$passphrase = hash("sha512", $passphrase."a", true);
		if (false !== $passphrase) {
			$result = hash_hmac("sha256", $encrypted, $passphrase);
		}

		return $result;
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

	function getFilelist($argv) {
		$result = null;

		if (1 < count($argv)) {
			$result = [];
			for ($i = 1; $i < count($argv); $i++) {
				$filename = $argv[$i];
				if (0 < strlen($filename)) {
					if ("/" !== $filename[0]) {
						$filename = concatPath(DATADIRECTORY, $filename);
					}
				}

				$result[] = $filename;
			}
		} else {
			$result = recursiveScandir();
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

	function readFilecache() {
		$result = false;

		if (is_file(STORAGES)) {
			$files = file(STORAGES, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			if (false !== $files) {
				if (0 < count($files)) {
					$storages = [];
					foreach ($files as $files_item) {
						$id   = substr($files_item, 0, strpos($files_item, ","));
						$name = substr($files_item, strpos($files_item, ",")+1);

						if (false !== strpos($name, "::")) {
							$type = substr($name, 0, strpos($name, "::"));
							$name = substr($name, strpos($name, "::")+2);

							if ("home" === $type) {
								$storages[$id] = concatPath(DATADIRECTORY, $name);
							} else {
								$storages[$id] = $name;
							}
						}
					}

					if (is_file(FILECACHE)) {
						$files = file(FILECACHE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
						if (false !== $files) {
							if (0 < count($files)) {
								$result = [];
								foreach ($files as $files_item) {
									$storage  = substr($files_item, 0, strpos($files_item, ","));
									$filename = substr($files_item, strpos($files_item, ",")+1, strrpos($files_item, ",")-strpos($files_item, ",")-1);
									$version  = substr($files_item, strrpos($files_item, ",")+1);

									if (array_key_exists($storage, $storages)) {
										$result[concatPath($storages[$storage], $filename)] = $version;
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

	function checkFile($file, $filekey, $masterkey, $sharekey, $version = 0, $position = 0) {
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
						$positionModified = ($i-1);
						if (intval(ceil($strlen/BLOCKSIZE)) === ($i+1)) {
							$positionModified .= "end";
						}
						debug("\$position = ".var_export($positionModified, true), DEBUG_DEBUG);

						$meta = splitMetaData($block);
						debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

						if (array_key_exists("encrypted", $meta) &&
						    array_key_exists("signature", $meta) &&
						    (false !== $meta["signature"])) {
						    	$signature = createSignature($meta["encrypted"], $filekeyModified.$version.$positionModified);
							debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

							if (false !== $signature) {
								$temp = checkSignature($signature, $meta["signature"]);
							}
						}
					}

					$result = ($result && $temp);
				}
			}
		}

		return $result;
	}

	function checkPrivateKey($file, $password, $keyid, $version = 0, $position = 0) {
		$result = false;

		debug("\$keyid = ".var_export($keyid, true), DEBUG_DEBUG);
		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);
		debug("\$position = ".var_export($position, true), DEBUG_DEBUG);
	
		$header = parseHeader($file);
		debug("\$header = ".var_export($header, true), DEBUG_DEBUG);

		$meta = splitMetaData($file);
		debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

		if (array_key_exists("encrypted", $meta) &&
		    array_key_exists("signature", $meta) &&
		    (false !== $meta["signature"])) {
			$passwordModified = $password;
			if (array_key_exists("cipher", $header) &&
			    array_key_exists("keyFormat", $header) &&
			    ("hash" === $header["keyFormat"])) {
				$passwordModified = generatePasswordHash($passwordModified, $header["cipher"], $keyid);
			}

			$signature = createSignature(stripHeader($meta["encrypted"]), $passwordModified.$version.$position);
			debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

			if (false !== $signature) {
				$result = checkSignature($signature, $meta["signature"]);
			}
		}

		return $result;
	}

	function checkMasterKey($file, $version = 0, $position = 0) {
		$result = false;

		$masterkeyid = getMasterKeyId();
		if (false !== $masterkeyid) {
			$result = checkPrivateKey($file, SECRET, $masterkeyid, $version, $position);
		}

		return $result;
	}

	function checkPubShareKey($file, $version = 0, $position = 0) {
		return checkPrivateKey($file, "", "", $version, $position);
	}

	function fixFile($file, $filename, $filekey, $masterkey, $sharekey, $version = 0, $position = 0) {
		$result = false;

		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);
		debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

		$masterkeyid = getMasterKeyId();
		debug("\$masterkeyid = ".var_export($masterkeyid, true), DEBUG_DEBUG);

		if (false !== $masterkeyid) {
 			$masterkeyModified = decryptPrivateKey($masterkey, SECRET, $masterkeyid);
			if (openssl_open($filekey, $filekeyModified, $sharekey, $masterkeyModified)) {

				$fileModified = $file;
				$strlen       = strlen($file);
				for ($i = 0; $i < intval(ceil($strlen/BLOCKSIZE)); $i++) {
					$block = substr($file, $i*BLOCKSIZE, BLOCKSIZE);

					if (0 === $i) {
						$header = parseHeader($block);
						debug("\$header = ".var_export($header, true), DEBUG_DEBUG);
					} else {
						$positionModified = ($i-1);
						if (intval(ceil($strlen/BLOCKSIZE)) === ($i+1)) {
							$positionModified .= "end";
						}
						debug("\$position = ".var_export($positionModified, true), DEBUG_DEBUG);

						$meta = splitMetaData($block);
						debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

						if (array_key_exists("encrypted", $meta) &&
						    array_key_exists("signature", $meta) &&
						    (false !== $meta["signature"])) {
						    	$signature = createSignature($meta["encrypted"], $filekeyModified.$version.$positionModified);
							debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

							if (false !== $signature) {
								$signaturePos = 0;
								if (intval(ceil($strlen/BLOCKSIZE)) > ($i+1)) {
									$signaturePos = ($i+1)*BLOCKSIZE;
								}
								$signaturePos -= strlen($signature);
								if (hasPadding($block, true)) {
									$signaturePos -= strlen("xxx");
								}

								$fileModified = substr_replace($fileModified, $signature, $signaturePos, strlen($signature));
							}
						}
					}
				}

				if (checkFile($fileModified, $filekey, $masterkey, $sharekey, $version, $position)) {
					$result = (false !== file_put_contents($filename, $fileModified));
				}
			}
		}

		return $result;
	}

	function fixPrivateKey($file, $filename, $password, $keyid, $version = 0, $position = 0) {
		$result = false;

		debug("\$filename = ".var_export($filename, true), DEBUG_DEBUG);
		debug("\$keyid = ".var_export($keyid, true), DEBUG_DEBUG);
		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);
		debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

		$header = parseHeader($file);
		debug("\$header = ".var_export($header, true), DEBUG_DEBUG);

		$meta = splitMetaData($file);
		debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

		if (array_key_exists("encrypted", $meta) &&
		    array_key_exists("signature", $meta) &&
		    (false !== $meta["signature"])) {
			$passwordModified = $password;
			if (array_key_exists("cipher", $header) &&
			    array_key_exists("keyFormat", $header) &&
			    ("hash" === $header["keyFormat"])) {
				$passwordModified = generatePasswordHash($passwordModified, $header["cipher"], $keyid);
			}

			$signature = createSignature(stripHeader($meta["encrypted"]), $passwordModified.$version.$position);
			debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

			if (false !== $signature) {
				$signaturePos = -strlen($signature);
				if (hasPadding($file, true)) {
					$signaturePos -= strlen("xxx");
				}

				$fileModified = substr_replace($file, $signature, $signaturePos, strlen($signature));

				if (checkPrivateKey($fileModified, $password, $keyid, $version, $position)) {
					$result = (false !== file_put_contents($filename, $fileModified));
				}
			}
		}

		return $result;
	}

	function fixMasterKey($file, $filename, $version = 0, $position = 0) {
		$result = false;

		$masterkeyid = getMasterKeyId();
		if (false !== $masterkeyid) {
			$result = fixPrivateKey($file, $filename, SECRET, $masterkeyid, $version, $position);
		}

		return $result;
	}

	function fixPubShareKey($file, $filename, $version = 0, $position = 0) {
		return fixPrivateKey($file, $filename, "", "", $version, $position);
	}

	function handleMasterKey($filename, $filecache) {
		if (!array_key_exists($filename, $filecache)) {
			debug("$filename: File not found in filecache.", DEBUG_DEFAULT);
		} else {
			$version = intval($filecache[$filename]);

			if (!is_file($filename)) {
				debug("$filename: File is not a file.", DEBUG_DEFAULT);
			} else {
				$file = file_get_contents($filename);
				if (false === $file) {
					debug("$filename: File could not be read.", DEBUG_DEFAULT);
				} else {
					if (!checkMasterKey($file, $version)) {
						debug("$filename: Master key signature mismatch.", DEBUG_DEFAULT);

						if (FIXSIGNATURES) {
							if (!fixMasterKey($file, $filename, $version)) {
								debug("$filename: Master key signature not fixed.", DEBUG_DEFAULT);
							} else {
								debug("$filename: Master key signature fixed.", DEBUG_DEFAULT);
							}
						}
					} else {
						debug("$filename: OK", DEBUG_INFO);
					}
				}
			}
		}	
	}

	function handlePubShareKey($filename, $filecache) {
		if (!array_key_exists($filename, $filecache)) {
			debug("$filename: File not found in filecache.", DEBUG_DEFAULT);
		} else {
			$version = intval($filecache[$filename]);

			if (!is_file($filename)) {
				debug("$filename: File is not a file.", DEBUG_DEFAULT);
			} else {
				$file = file_get_contents($filename);
				if (false === $file) {
					debug("$filename: File could not be read.", DEBUG_DEFAULT);
				} else {
					if (!checkPubShareKey($file, $version)) {
						debug("$filename: Pub share key signature mismatch.", DEBUG_DEFAULT);

						if (FIXSIGNATURES) {
							if (!fixPubShareKey($file, $filename, $version)) {
								debug("$filename: Pub share key signature not fixed.", DEBUG_DEFAULT);
							} else {
								debug("$filename: Pub share key signature fixed.", DEBUG_DEFAULT);
							}
						}
					} else {
						debug("$filename: OK", DEBUG_INFO);
					}
				}
			}
		}
	}

	function handleFile($filename, $filecache, $username, $datafilename, $istrashbin = false) {
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

			if (!array_key_exists($filename, $filecache)) {
				debug("$filename: File not found in filecache.", DEBUG_DEFAULT);
			} else {
				$version = intval($filecache[$filename]);

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
												if (!checkFile($file, $filekey, $masterkey, $sharekey, $version)) {
													debug("$filename: File signature mismatch.", DEBUG_DEFAULT);

													if (FIXSIGNATURES) {
														if (!fixFile($file, $filename, $filekey, $masterkey, $sharekey, $version)) {
															debug("$filename: File signature not fixed.", DEBUG_DEFAULT);
														} else {
															debug("$filename: File signature fixed.", DEBUG_DEFAULT);
														}
													}
												} else {
													debug("$filename: OK", DEBUG_INFO);
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
		}
	}

	function main($argv) {
		$result = 0;

		$filecache = readFilecache();
		debug("\$filecache = ".var_export($filecache, true), DEBUG_DEBUG);

		if (false === $filecache) {
			debug("Filecache could not be read.", DEBUG_DEFAULT);
		} else {
			$filelist = getFilelist($argv);
			debug("\$filelist = ".var_export($filelist, true), DEBUG_DEBUG);

			foreach ($filelist as $filename) {
				debug("##################################################", DEBUG_DEBUG);
				debug("\$filename = ".var_export($filename, true), DEBUG_DEBUG);

				if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                     "files_encryption/OC_DEFAULT_MODULE/master_[0-9a-z]+\.privateKey$@", $filename)) {
					handleMasterKey($filename, $filecache);
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "files_encryption/OC_DEFAULT_MODULE/pubShare_[0-9a-z]+\.privateKey$@", $filename)) {
					handlePubShareKey($filename, $filecache);
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "(?<username>[^/]+)/files/(?<datafilename>.+)$@", $filename, $matches)) {
					handleFile($filename, $filecache, $matches["username"], $matches["datafilename"], false);
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "(?<username>[^/]+)/files_trashbin/files/(?<datafilename>.+)$@", $filename, $matches)) {
					handleFile($filename, $filecache, $matches["username"], $matches["datafilename"], true);
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "(?<username>[^/]+)/files_versions/(?<datafilename>.+)\.v[0-9]+$@", $filename, $matches)) {
					handleFile($filename, $filecache, $matches["username"], $matches["datafilename"], false);
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "(?<username>[^/]+)/files_trashbin/versions/(?<datafilename>.+)\.v[0-9]+(?<deletetime>\.d[0-9]+)$@", $filename, $matches)) {
					handleFile($filename, $filecache, $matches["username"], $matches["datafilename"].$matches["deletetime"], true);
				} else {
					debug("$filename: File has unknown filename format.", DEBUG_INFO);
				}

				debug("##################################################", DEBUG_DEBUG);
			}
		}

		return $result;
	}

	exit(main($argv));


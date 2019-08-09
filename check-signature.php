<?php

	# check-signature.php
	#
	# Copyright (c) 2019, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./check-signature.php [<filename>*]
	#
	#
	# preparation of PostgreSQL:
	# ==========================
	#
	# sudo -u <dbuser> psql -d <dbname>
	#
	# \COPY (SELECT storage, path, encrypted FROM oc_filecache) TO '/tmp/filecache.csv' WITH CSV DELIMITER ',';
	# \COPY (SELECT numeric_id, id FROM oc_storages) TO '/tmp/storages.csv' WITH CSV DELIMITER ',';
	# \q
	#
	#
	# preparation of MariaDB/MySQL:
	# =============================
	#
	# sudo mysql -D <dbname>
	#
	# SELECT storage, path, encrypted FROM oc_filecache INTO OUTFILE '/var/lib/mysql-files/filecache.csv' FIELDS ESCAPED BY '' TERMINATED BY ',' LINES TERMINATED BY '\n';
	# SELECT numeric_id, id FROM oc_storages INTO OUTFILE '/var/lib/mysql-files/storages.csv' FIELDS ESCAPED BY '' TERMINATED BY ',' LINES TERMINATED BY '\n';
	# QUIT;
	#
	# sudo mv /var/lib/mysql-files/filecache.csv /tmp/
	# sudo mv /var/lib/mysql-files/storages.csv /tmp/
	#
	#
	# file structure of /tmp/filecache.csv:
	# =====================================
	#
	# <storage>,<path>,<encrypted>
	# <storage>,<path>,<encrypted>
	# <storage>,<path>,<encrypted>
	# ...
	# <storage>,<path>,<encrypted>
	#
	#
	# file structure of /tmp/storages.csv:
	# ====================================
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
	define("FIX_DATABASE",  1);
	define("FIX_FILE",      2);
	define("FIX_NONE",      0);
	define("HEADER_END",    "HEND");
	define("HEADER_START",  "HBEGIN");
	define("KEY_MASTER",    0);
	define("KEY_PUBSHARE",  1);
	define("KEY_RECOVERY",  2);
	define("KEY_USER",      3);

	// nextcloud definitions - you can get these values from config/config.php
	define("DATADIRECTORY", "");
	define("DBTABLEPREFIX", "oc_");
	define("INSTANCEID",    "");
	define("SECRET",        "");

	// custom definitions
	define("DEBUGLEVEL",        DEBUG_DEFAULT);
	define("FILECACHE",         "/tmp/filecache.csv");
	define("FIXSIGNATURES",     FIX_NONE); // CAUTION: setting this to FIX_FILE may break your files
	define("KEYTYPE",           KEY_MASTER);
	define("MAXVERSION",        50);
	define("RECOVERY_PASSWORD", "");
	define("STORAGES",          "/tmp/storages.csv");
	define("USER_NAME",         "");
	define("USER_PASSWORD",     "");

	// user password definitions - used to check user private keys
	// replace "USERNAME" with the actual username
	// define("USER_PASSWORD_USERNAME", "");
	// define("USER_PASSWORD_USERNAME", "");
	// define("USER_PASSWORD_USERNAME", "");

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
		$result = false;

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

	function getKeyFilename($keyname) {
		$result = false;

		switch (KEYTYPE) {
			case KEY_MASTER:
			case KEY_PUBSHARE:
			case KEY_RECOVERY:
				$result = concatPath(DATADIRECTORY, "files_encryption/OC_DEFAULT_MODULE/".$keyname.".privateKey");
				break;

			case KEY_USER:
				$result = concatPath(DATADIRECTORY, $keyname."/files_encryption/OC_DEFAULT_MODULE/".$keyname.".privateKey");
				break;
		}

		return $result;
	}

	function getKeyId() {
		$result = false;

		switch (KEYTYPE) {
			case KEY_MASTER:
				$result = getMasterKeyName();
				break;

			case KEY_PUBSHARE:
				$result = "";
				break;

			case KEY_RECOVERY:
				$result = "";
				break;

			case KEY_USER:
				$result = USER_NAME;
				break;
		}

		return $result;
	}

	function getKeyName() {
		$result = false;

		switch (KEYTYPE) {
			case KEY_MASTER:
				$result = getMasterKeyName();
				break;

			case KEY_PUBSHARE:
				$result = getPubShareKeyName();
				break;

			case KEY_RECOVERY:
				$result = getRecoveryKeyName();
				break;

			case KEY_USER:
				$result = USER_NAME;
				break;
		}

		return $result;
	}

	function getKeyPassword() {
		$result = false;

		switch (KEYTYPE) {
			case KEY_MASTER:
				$result = SECRET;
				break;

			case KEY_PUBSHARE:
				$result = "";
				break;

			case KEY_RECOVERY:
				$result = RECOVERY_PASSWORD;
				break;

			case KEY_USER:
				$result = USER_PASSWORD;
				break;
			}

		return $result;
	}

	function getUserPassword($username) {
		$result = false;

		if (USER_NAME === $username) {
			$result = USER_PASSWORD;
		} else {
			if (defined("USER_PASSWORD_".strtoupper($username))) {
				$result = constant("USER_PASSWORD_".strtoupper($username));
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

	function getMasterKeyName() {
		$result = false;

		$filelist = recursiveScandir(concatPath(DATADIRECTORY, "files_encryption/OC_DEFAULT_MODULE/"));
		foreach ($filelist as $filename) {
			if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                     "files_encryption/OC_DEFAULT_MODULE/(?<keyid>master_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
				$result = $matches["keyid"];

				break;
			}
		}

		return $result;
	}

	function getPubShareKeyName() {
		$result = false;

		$filelist = recursiveScandir(concatPath(DATADIRECTORY, "files_encryption/OC_DEFAULT_MODULE/"));
		foreach ($filelist as $filename) {
			if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                     "files_encryption/OC_DEFAULT_MODULE/(?<keyid>pubShare_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
				$result = $matches["keyid"];

				break;
			}
		}

		return $result;
	}

	function getRecoveryKeyName() {
		$result = false;

		$filelist = recursiveScandir(concatPath(DATADIRECTORY, "files_encryption/OC_DEFAULT_MODULE/"));
		foreach ($filelist as $filename) {
			if (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
			                     "files_encryption/OC_DEFAULT_MODULE/(?<keyid>recoveryKey_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
				$result = $matches["keyid"];

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

							// make sure that file name is not enclosed in quotes
							if ((2 <= strlen($name)) &&
							    ("\"" === $name[0]) &&
							    ("\"" === $name[strlen($name)-1])) {
								$name = substr($name, 1, -1);
							}

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
										$result[concatPath($storages[$storage], $filename)] = ["encrypted" => $version, "path" => $filename, "storage" => $storage];
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

	function checkFile($file, $filekey, $key, $sharekey, $version = 0) {
		$result = false;

		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);

		$keyid = getKeyId();
		debug("\$keyid = ".var_export($keyid, true), DEBUG_DEBUG);

		if (false !== $keyid) {
			$keyModified = decryptPrivateKey($key, getKeyPassword(), $keyid);
			if (openssl_open($filekey, $filekeyModified, $sharekey, $keyModified)) {
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

						if (array_key_exists("encrypted", $meta) &&
						    array_key_exists("signature", $meta) &&
						    (false !== $meta["signature"])) {
							// use dynamic position for file
							$position = ($i-1);
							if (intval(ceil($strlen/BLOCKSIZE)) === ($i+1)) {
								$position .= "end";
							}
							debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

							$signature = createSignature($meta["encrypted"], $filekeyModified.$version.$position);
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

	function checkPrivateKey($file, $password, $keyid, $version = 0) {
		$result = false;

		debug("\$keyid = ".var_export($keyid, true), DEBUG_DEBUG);
		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);
	
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

			// use static position for private key file
			$position = 0;
			debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

			$signature = createSignature(stripHeader($meta["encrypted"]), $passwordModified.$version.$position);
			debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

			if (false !== $signature) {
				$result = checkSignature($signature, $meta["signature"]);
			}
		}

		return $result;
	}

	function checkMasterKey($file, $version = 0) {
		$result = false;

		$keyname = getMasterKeyName();
		if (false !== $keyname) {
			$result = checkPrivateKey($file, SECRET, $keyname, $version);
		}

		return $result;
	}

	function checkPubShareKey($file, $version = 0) {
		return checkPrivateKey($file, "", "", $version);
	}

	function checkRecoveryKey($file, $version = 0) {
		return checkPrivateKey($file, RECOVERY_PASSWORD, "", $version);
	}

	function checkUserKey($file, $username, $version = 0) {
		$result = false;

		$password = getUserPassword($username);
		if (false !== $password) {
			$result = checkPrivateKey($file, $password, $username, $version);
		}

		return $result;
	}

	function fixDatabase($file, $filekey, $key, $sharekey, $storage, $path) {
		$result = false;

		$keyid = getKeyId();
		debug("\$keyid = ".var_export($keyid, true), DEBUG_DEBUG);

		if (false !== $keyid) {
			$keyModified = decryptPrivateKey($key, getKeyPassword(), $keyid);
			if (openssl_open($filekey, $filekeyModified, $sharekey, $keyModified)) {
				$strlen = strlen($file);
				for ($i = 0; $i <= 1; $i++) {
					$block = substr($file, $i*BLOCKSIZE, BLOCKSIZE);

					if (0 === $i) {
						$header = parseHeader($block);
						debug("\$header = ".var_export($header, true), DEBUG_DEBUG);
					} else {
						$meta = splitMetaData($block);
						debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

						if (array_key_exists("encrypted", $meta) &&
						    array_key_exists("signature", $meta) &&
						    (false !== $meta["signature"])) {
							// use dynamic position for files
							$position = ($i-1);
							if (intval(ceil($strlen/BLOCKSIZE)) === ($i+1)) {
								$position .= "end";
							}
							debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

							for ($version = 0; $version <= MAXVERSION; $version++) {
								debug("\$version = ".var_export($version, true), DEBUG_DEBUG);

								$signature = createSignature($meta["encrypted"], $filekeyModified.$version.$position);
								debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

								if (false !== $signature) {
									if (checkSignature($signature, $meta["signature"])) {
										// we found the correct signature and now have to calculate the unencrypted file size
										debug("\$strlen = ".var_export($strlen, true), DEBUG_DEBUG);

										// first try to find out the correct encryption padding length
										$encryptionPadding = 0;
										if (hasPadding($block, true)) {
											$encryptionPadding = strlen("xxx");
										} elseif (hasPadding($block, false)) {
											$encryptionPadding = strlen("xx");
										}
										debug("\$encryptionPadding = ".var_export($encryptionPadding, true), DEBUG_DEBUG);

										// then try to find out the correct base64 padding length
										$base64Padding = 0;
										while ("=" === $file[($strlen - (6 + 16 + 7 + 64 + $encryptionPadding) - ($base64Padding + 1))]) {
											$base64Padding++;
										}
										debug("\$base64Padding = ".var_export($base64Padding, true), DEBUG_DEBUG);

										// finally calculate the file size
										$size = intval(floor(($strlen - 8192 - ceil(($strlen - 8192) / 8192) * (6 + 16 + 7 + 64 + $encryptionPadding) - $base64Padding) / 4 * 3));
										debug("\$size = ".var_export($size, true), DEBUG_DEBUG);

										// WARNING: using addslashes() to escape a string is not secure for SQL queries,
										// unfortunately correct ways like mysqli_real_escape_string() require an active databse connection
										$result = "UPDATE ".DBTABLEPREFIX."filecache SET encrypted=$version, size=$size WHERE storage=$storage AND path='".addslashes($path)."';";
										break;
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

	function fixFile($file, $filename, $filekey, $key, $sharekey, $version = 0) {
		$result = false;

		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);

		$keyid = getKeyId();
		debug("\$keyid = ".var_export($keyid, true), DEBUG_DEBUG);

		if (false !== $keyid) {
			$keyModified = decryptPrivateKey($key, getKeyPassword(), $keyid);
			if (openssl_open($filekey, $filekeyModified, $sharekey, $keyModified)) {
				$fileModified = $file;
				$strlen       = strlen($file);
				for ($i = 0; $i < intval(ceil($strlen/BLOCKSIZE)); $i++) {
					$block = substr($file, $i*BLOCKSIZE, BLOCKSIZE);

					if (0 === $i) {
						$header = parseHeader($block);
						debug("\$header = ".var_export($header, true), DEBUG_DEBUG);
					} else {
						$meta = splitMetaData($block);
						debug("\$meta = ".var_export($meta, true), DEBUG_DEBUG);

						if (array_key_exists("encrypted", $meta) &&
						    array_key_exists("signature", $meta) &&
						    (false !== $meta["signature"])) {
							// use dynamic position for files
							$position = ($i-1);
							if (intval(ceil($strlen/BLOCKSIZE)) === ($i+1)) {
								$position .= "end";
							}
							debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

							$signature = createSignature($meta["encrypted"], $filekeyModified.$version.$position);
							debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

							if (false !== $signature) {
								$signaturePos = 0;
								if (intval(ceil($strlen/BLOCKSIZE)) > ($i+1)) {
									$signaturePos = ($i+1)*BLOCKSIZE;
								}
								$signaturePos -= strlen($signature);
								if (hasPadding($block, true)) {
									$signaturePos -= strlen("xxx");
								} elseif (hasPadding($block, false)) {
									$signaturePos -= strlen("xx");
								}

								#$fileModified = substr_replace($fileModified, $signature, $signaturePos, strlen($signature));
								for ($j = 0; $j < strlen($signature); $j++) {
									$fileModified[$signaturePos+$j] = $signature[$j];
								}
							}
						}
					}
				}

				if (checkFile($fileModified, $filekey, $key, $sharekey, $version)) {
					$result = (false !== file_put_contents($filename, $fileModified));
				}
			}
		}

		return $result;
	}

	function fixPrivateKeyFile($file, $filename, $password, $keyid, $version = 0) {
		$result = false;

		debug("\$filename = ".var_export($filename, true), DEBUG_DEBUG);
		debug("\$keyid = ".var_export($keyid, true), DEBUG_DEBUG);
		debug("\$version = ".var_export($version, true), DEBUG_DEBUG);

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

			// use static position for private key file
			$position = 0;
			debug("\$position = ".var_export($position, true), DEBUG_DEBUG);

			$signature = createSignature(stripHeader($meta["encrypted"]), $passwordModified.$version.$position);
			debug("\$signature = ".var_export($signature, true), DEBUG_DEBUG);

			if (false !== $signature) {
				$signaturePos = -strlen($signature);
				if (hasPadding($file, true)) {
					$signaturePos -= strlen("xxx");
				}

				#$fileModified = substr_replace($file, $signature, $signaturePos, strlen($signature));
				$fileModified = $file;
				for ($j = 0; $j < strlen($signature); $j++) {
					$fileModified[$signaturePos+$j] = $signature[$j];
				}

				if (checkPrivateKey($fileModified, $password, $keyid, $version)) {
					$result = (false !== file_put_contents($filename, $fileModified));
				}
			}
		}

		return $result;
	}

	function fixMasterKeyFile($file, $filename, $version = 0) {
		$result = false;

		$keyname = getMasterKeyName();
		if (false !== $keyname) {
			$result = fixPrivateKeyFile($file, $filename, SECRET, $keyname, $version);
		}

		return $result;
	}

	function fixPubShareKeyFile($file, $filename, $version = 0) {
		return fixPrivateKeyFile($file, $filename, "", "", $version);
	}

	function fixRecoveryKeyFile($file, $filename, $version = 0) {
		return fixPrivateKeyFile($file, $filename, RECOVERY_PASSWORD, "", $version);
	}

	function fixUserKeyFile($file, $filename, $username, $version = 0) {
		$result = false;

		$password = getUserPassword($username);
		if (false !== $password) {
			$result = fixPrivateKeyFile($file, $filename, $password, $username, $version);
		}

		return $result;
	}

	function handleMasterKey($filename, $filecache) {
		if (!array_key_exists($filename, $filecache)) {
			debug("$filename: File not found in filecache.", DEBUG_DEFAULT);
		} else {
			$version = intval($filecache[$filename]["encrypted"]);

			if (!is_file($filename)) {
				debug("$filename: File is not a file.", DEBUG_DEFAULT);
			} else {
				$file = file_get_contents($filename);
				if (false === $file) {
					debug("$filename: File could not be read.", DEBUG_DEFAULT);
				} else {
					if (!checkMasterKey($file, $version)) {
						debug("$filename: Master key signature mismatch.", DEBUG_DEFAULT);

						switch (FIXSIGNATURES) {
							case FIX_DATABASE:
								debug("$filename: Fix database not supported for master key.", DEBUG_DEFAULT);
								break;

							case FIX_FILE:
								if (!fixMasterKeyFile($file, $filename, $version)) {
									debug("$filename: Master key signature not fixed.", DEBUG_DEFAULT);
								} else {
									debug("$filename: Master key signature fixed.", DEBUG_DEFAULT);
								}
								break;
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
			$version = intval($filecache[$filename]["encrypted"]);

			if (!is_file($filename)) {
				debug("$filename: File is not a file.", DEBUG_DEFAULT);
			} else {
				$file = file_get_contents($filename);
				if (false === $file) {
					debug("$filename: File could not be read.", DEBUG_DEFAULT);
				} else {
					if (!checkPubShareKey($file, $version)) {
						debug("$filename: Pub share key signature mismatch.", DEBUG_DEFAULT);

						switch (FIXSIGNATURES) {
							case FIX_DATABASE:
								debug("$filename: Fix database not supported for pub share key.", DEBUG_DEFAULT);
								break;

							case FIX_FILE:
								if (!fixPubShareKeyFile($file, $filename, $version)) {
									debug("$filename: Pub share key signature not fixed.", DEBUG_DEFAULT);
								} else {
									debug("$filename: Pub share key signature fixed.", DEBUG_DEFAULT);
								}
								break;
						}
					} else {
						debug("$filename: OK", DEBUG_INFO);
					}
				}
			}
		}
	}

	function handleRecoveryKey($filename, $filecache) {
		if (!array_key_exists($filename, $filecache)) {
			debug("$filename: File not found in filecache.", DEBUG_DEFAULT);
		} else {
			$version = intval($filecache[$filename]["encrypted"]);

			if (!is_file($filename)) {
				debug("$filename: File is not a file.", DEBUG_DEFAULT);
			} else {
				$file = file_get_contents($filename);
				if (false === $file) {
					debug("$filename: File could not be read.", DEBUG_DEFAULT);
				} else {
					if (!checkRecoveryKey($file, $version)) {
						debug("$filename: Recovery key signature mismatch.", DEBUG_DEFAULT);

						switch (FIXSIGNATURES) {
							case FIX_DATABASE:
								debug("$filename: Fix database not supported for recovery key.", DEBUG_DEFAULT);
								break;

							case FIX_FILE:
								if (!fixRecoveryKeyFile($file, $filename, $version)) {
									debug("$filename: Recovery key signature not fixed.", DEBUG_DEFAULT);
								} else {
									debug("$filename: Recovery key signature fixed.", DEBUG_DEFAULT);
								}
								break;
						}
					} else {
						debug("$filename: OK", DEBUG_INFO);
					}
				}
			}
		}
	}

	function handleUserKey($filename, $filecache, $username) {
		if (!array_key_exists($filename, $filecache)) {
			debug("$filename: File not found in filecache.", DEBUG_DEFAULT);
		} else {
			$version = intval($filecache[$filename]["encrypted"]);

			if (!is_file($filename)) {
				debug("$filename: File is not a file.", DEBUG_DEFAULT);
			} else {
				$file = file_get_contents($filename);
				if (false === $file) {
					debug("$filename: File could not be read.", DEBUG_DEFAULT);
				} else {
					if (!checkUserKey($file, $username, $version)) {
						debug("$filename: User key signature mismatch.", DEBUG_DEFAULT);

						switch (FIXSIGNATURES) {
							case FIX_DATABASE:
								debug("$filename: Fix database not supported for user key.", DEBUG_DEFAULT);
								break;

							case FIX_FILE:
								if (!fixUserKeyFile($file, $filename, $username, $version)) {
									debug("$filename: User key signature not fixed.", DEBUG_DEFAULT);
								} else {
									debug("$filename: User key signature fixed.", DEBUG_DEFAULT);
								}
								break;
						}
					} else {
						debug("$filename: OK", DEBUG_INFO);
					}
				}
			}
		}
	}

	function handleFile($filename, $filecache, $username, $datafilename, $istrashbin = false) {
		$keyname = getKeyName();
		if (false === $keyname) {
			debug("$filename: Key ID could not be retrieved.", DEBUG_DEFAULT);
		} else {
			$keyfilename = getKeyFilename($keyname);

			if ($istrashbin) {
				$filekeyfilename  = concatPath(DATADIRECTORY,
					                             $username."/files_encryption/keys/files_trashbin/files/".$datafilename."/OC_DEFAULT_MODULE/fileKey");
				$sharekeyfilename = concatPath(DATADIRECTORY,
				                               $username."/files_encryption/keys/files_trashbin/files/".$datafilename."/OC_DEFAULT_MODULE/".$keyname.".shareKey");
			} else {
				$filekeyfilename  = concatPath(DATADIRECTORY,
				                               $username."/files_encryption/keys/files/".$datafilename."/OC_DEFAULT_MODULE/fileKey");
				$sharekeyfilename = concatPath(DATADIRECTORY,
				                               $username."/files_encryption/keys/files/".$datafilename."/OC_DEFAULT_MODULE/".$keyname.".shareKey");
			}

			if (!array_key_exists($filename, $filecache)) {
				debug("$filename: File not found in filecache.", DEBUG_DEFAULT);
			} else {
				$version = intval($filecache[$filename]["encrypted"]);
				if ((0 === $version) && (FIX_DATABASE !== FIXSIGNATURES)) {
					debug("$filename: Filecache contains zero version for file.", DEBUG_DEFAULT);
				} else {
					if (!is_file($filename)) {
						debug("$filename: File is not a file.", DEBUG_DEFAULT);
					} else {
						if (!is_file($keyfilename)) {
							debug("$filename: Key is not a file.", DEBUG_DEFAULT);
						} else {
							if (!is_file($filekeyfilename)) {
								debug("$filename: Filekey is not a file.", DEBUG_DEFAULT);
							} else {
								if (!is_file($sharekeyfilename)) {
									debug("$filename: Sharekey is not a file.", DEBUG_DEFAULT);
								} else {
									$file = file_get_contents($filename);
									if (false === $file) {
										debug("$filename: File could not be read.", DEBUG_DEFAULT);
									} else {
										$key = file_get_contents($keyfilename);
										if (false === $key) {
											debug("$filename: Key could not be read.", DEBUG_DEFAULT);
										} else {
											$filekey = file_get_contents($filekeyfilename);
											if (false === $filekey) {
												debug("$filename: Filekey could not be read.", DEBUG_DEFAULT);
											} else {
												$sharekey = file_get_contents($sharekeyfilename);
												if (false === $sharekey) {
													debug("$filename: Sharekey could not be read.", DEBUG_DEFAULT);
												} else {
													if (!checkFile($file, $filekey, $key, $sharekey, $version)) {
														debug("$filename: File signature mismatch.", DEBUG_DEFAULT);

														switch (FIXSIGNATURES) {
															case FIX_DATABASE:
																$query = fixDatabase($file, $filekey, $key, $sharekey, $filecache[$filename]["storage"], $filecache[$filename]["path"]);
																if (false === $query) {
																	debug("$filename: Database not fixed.", DEBUG_DEFAULT);
																} else {
																	debug("$filename: $query", DEBUG_DEFAULT);
																}
																break;

															case FIX_FILE:
																if (!fixFile($file, $filename, $filekey, $key, $sharekey, $version)) {
																	debug("$filename: File signature not fixed.", DEBUG_DEFAULT);
																} else {
																	debug("$filename: File signature fixed.", DEBUG_DEFAULT);
																}
																break;
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
				                           "files_encryption/OC_DEFAULT_MODULE/recoveryKey_[0-9a-z]+\.privateKey$@", $filename)) {
					handleRecoveryKey($filename, $filecache);
				} elseif (1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                           "(?<username>[^/]+)/files/(?<datafilename>.+)$@", $filename, $matches)) {
					handleFile($filename, $filecache, $matches["username"], $matches["datafilename"], false);
				} elseif ((1 === preg_match("@^".preg_quote(concatPath(DATADIRECTORY, ""), "@").
				                            "(?<username>[^/]+)/files_encryption/OC_DEFAULT_MODULE/(?<username2>.+)\.privateKey$@", $filename, $matches)) &&
				          ($matches["username"] === $matches["username2"])) {
					handleUserKey($filename, $filecache, $matches["username"]);
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


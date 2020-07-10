<?php

	# decrypt-all-files.php
	#
	# Copyright (c) 2019-2020, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./decrypt-all-files.php <targetdir>
	#
	#
	# description:
	# ============
	#
	# This is script can save your precious files in cases where you encrypted them with the
	# Nextcloud Server Side Encryption and still have access to the data directory and the
	# Nextcloud configuration file ("config/config.php"). This script is able to decrypt locally
	# stored files within the data directory. It supports master-key encrypted files, user-key
	# encrypted files and can also use a rescue key (if enabled) and the public sharing key if
	# files had been publicly shared.
	#
	#
	# In order to use the script you have to configure the given values below:
	#
	# DATADIRECTORY     this is the location of the data directory of your Nextcloud instance,
	#                   if you copied or moved your data directory then you have to set this value accordingly,
	#                   this directory has to exist and contain the typical file structure of Nextcloud
	#
	# INSTANCEID        this is a value from the Nextcloud configuration file,
	#                   there does not seem to be another way to retrieve this value
	#
	# SECRET            this is a value from the Nextcloud configuration file,
	#                   there does not seem to be another way to retrieve this value
	#
	# RECOVERY_PASSWORD this is the password for the recovery key,
	#                   you can set this value if you activated the recovery feature of your Nextcloud instance,
	#                   leave this value empty if you did not acticate the recovery feature of your Nextcloud instance
	#
	# USER_PASSWORD_*   these are the passwords for the user keys,
	#                   you have to set these values if you disabled the master key encryption of your Nextcloud instance,
	#                   do not set these values if you did not disable the master key encryption your Nextcloud instance,
	#                   each value represents a (username, password) pair and you can set as many pairs as necessary,
	#                   the username has to be written in uppercase characters and be prepended with "USER_PASSWORD_",
	#                   Example: if the username was "beispiel" and the password of that user was "example" then the value
	#                            has to be set as: define("USER_PASSWORD_BEISPIEL", "example");
	#
	#
	# execution:
	# ==========
	#
	# To execute the script you have to call it in the following way:
	#
	# php ./decrypt-all-files.php <targetdir>
	#
	# <targetdir> this is the target directory where the decrypted files get stored, the target directory has to already exist
	#             and it has to be empty, make sure that there is enough space to store all files decrypted files in the target
	#             directory
	#
	# The execution may take a lot of time, depending on the power of your computer and on the number and size of your files.
	# Make sure that the script is able to run without interruption. As of now it does not have a resume feature. On servers you
	# can achieve this by starting the script within a screen session. Also, the script currently does not support external
	# storages. If you need this specific feature then please contact the author.

	// static definitions
	define("BLOCKSIZE",    8192);
	define("HEADER_END",   "HEND");
	define("HEADER_START", "HBEGIN");

	// nextcloud definitions - you can get these values from config/config.php
	define("DATADIRECTORY", "");
	define("INSTANCEID",    "");
	define("SECRET",        "");

	// recovery password definition
	define("RECOVERY_PASSWORD", "");

	// user password definitions
	// replace "USERNAMEA", "USERNAMEB", "USERNAMEC" with the actual usernames
	// you can add or remove entries as necessary
	// define("USER_PASSWORD_USERNAMEA", "");
	// define("USER_PASSWORD_USERNAMEB", "");
	// define("USER_PASSWORD_USERNAMEC", "");

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
				                           "files_encryption/OC_DEFAULT_MODULE/(?<keyname>recoveryKey_[0-9a-z]+)\.privateKey$@", $filename, $matches)) {
					$keyname  = $matches["keyname"];
					$keyid    = "";
					$password = RECOVERY_PASSWORD;
				}

				if (null !== $keyname) {
					$file = file_get_contents($filename);
					if (false !== $file) {
						$key = decryptPrivateKey($file, $password, $keyid);
						if (false !== $key) {
							$result[$keyname] = $key;
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
					if (defined("USER_PASSWORD_".strtoupper($keyname))) {
						$password = constant("USER_PASSWORD_".strtoupper($keyname));
					}

					if (is_file($filename) && (null !== $password)) {
						$file = file_get_contents($filename);
						if (false !== $file) {
							$key = decryptPrivateKey($file, $password, $keyname);
							if (false !== $key) {
								$result[$keyname] = $key;
							}
						}
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

	function decryptBlock($header, $block, $secretkey) {
		$result = false;

		$meta = splitMetaData($block);
		if (array_key_exists("cipher", $header) &&
		    array_key_exists("encrypted", $meta) &&
		    array_key_exists("iv", $meta)) {
			$output = openssl_decrypt($meta["encrypted"], $header["cipher"], $secretkey, false, $meta["iv"]);
			if (false !== $output) {
				$result = $output;
			}
		}

		return $result;
	}

	function decryptFile($filename, $filekey, $sharekey, $privatekey, $target) {
		$result = false;

		if (openssl_open($filekey, $secretkey, $sharekey, $privatekey)) {
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

						while (BLOCKSIZE < strlen($buffer)) {
							$block  = substr($buffer, 0, BLOCKSIZE);
							$buffer = substr($buffer, BLOCKSIZE);

							// the first block contains the header
							if ($first) {
								$first  = false;
								$header = parseHeader($block);
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
		}

		return $result;
	}

	function decryptAllFiles($targetdir) {
		$result = 0;

		$privatekeys = decryptPrivateKeys();
		if (0 < count($privatekeys)) {
			$filelist = recursiveScandir(DATADIRECTORY, true);
			foreach ($filelist as $filename) {
				$success = false;

				$datafilename = null;
				$istrashbin   = false;
				$username     = null;

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
				}

				if (null !== $datafilename) {
					$filekey  = null;
					$keyname  = null;
					$sharekey = null;

					if ($istrashbin) {
						$filekey  = concatPath(DATADIRECTORY,
						                       $username."/files_encryption/keys/files_trashbin/files/".$datafilename."/OC_DEFAULT_MODULE/fileKey");

						foreach ($privatekeys as $key => $value) {
							$tmp = concatPath(DATADIRECTORY,
							                  $username."/files_encryption/keys/files_trashbin/files/".$datafilename."/OC_DEFAULT_MODULE/".$key.".shareKey");
							if (is_file($tmp)) {
								$keyname  = $key;
								$sharekey = $tmp;
								break;
							}
						}
					} else {
						$filekey  = concatPath(DATADIRECTORY,
						                       $username."/files_encryption/keys/files/".$datafilename."/OC_DEFAULT_MODULE/fileKey");

						foreach ($privatekeys as $key => $value) {
							$tmp = concatPath(DATADIRECTORY,
							                  $username."/files_encryption/keys/files/".$datafilename."/OC_DEFAULT_MODULE/".$key.".shareKey");
							if (is_file($tmp)) {
								$keyname  = $key;
								$sharekey = $tmp;
								break;
							}
						}
					}

					if (is_file($filekey) && is_file($sharekey) && (null !== $keyname)) {
						$filekey  = file_get_contents($filekey);
						$sharekey = file_get_contents($sharekey);
						$target   = concatPath($targetdir, substr($filename, strlen(DATADIRECTORY)));

						// try to recursively create the target subfolder
						if (!is_dir(dirname($target))) {
							mkdir(dirname($target), 0777, true);
						}

						$success = decryptFile($filename, $filekey, $sharekey, $privatekeys[$keyname], $target);
					}

					if ($success) {
						print($filename."\n");
					} else {
						print("ERROR: ".substr($filename, strlen(DATADIRECTORY))." FAILED\n");
						$result = 5;
					}
				}
			}
		} else {
			print("ERROR: COULD NOT DECRYPT ANY PRIVATE KEY\n");
			$result = 4;
		}

		return $result;
	}

	function main($argv) {
		$result = 0;

		if (is_dir(DATADIRECTORY)) {
			$targetdir = null;
			if (2 >= count($argv)) {
				$targetdir = $argv[1];
			}
			
			if ((null !== $targetdir) && is_dir($targetdir)) {
				$filelist = recursiveScandir($targetdir, false);
				if (0 === count($filelist)) {
					$result = decryptAllFiles($targetdir);
				} else {
					print("ERROR: TARGETDIR NOT EMPTY\n");
					$result = 3;
				}
			} else {
				print("ERROR: TARGETDIR NOT GIVEN OR DOES NOT EXIST\n");
				$result = 2;
			}
		} else {
			print("ERROR: DATADIRECTORY DOES NOT EXIST\n");
			$result = 1;
		}

		return $result;
	}

	exit(main($argv));

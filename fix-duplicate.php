<?php

	# fix-duplicate.php
	#
	# Copyright (c) 2019, SysEleven GmbH
	# All rights reserved.
	#
	#
	# usage:
	# ======
	#
	# php ./fix-duplicate.php
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
	define("DEBUG_DEBUG",   2);
	define("DEBUG_DEFAULT", 0);
	define("DEBUG_INFO",    1);

	// nextcloud definitions - you can get these values from config/config.php
	define("DATADIRECTORY", "");
	define("DBTABLEPREFIX", "oc_");

	// custom definitions
	define("DEBUGLEVEL", DEBUG_DEFAULT);
	define("FILECACHE",  "/tmp/filecache.csv");
	define("STORAGES",   "/tmp/storages.csv");

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
										$result[$storage.":".concatPath($storages[$storage], $filename)] = ["encrypted" => $version, "path" => $filename, "storage" => $storage];
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

	function main($argv) {
		$result = 0;

		$filecache = readFilecache();
		debug("\$filecache = ".var_export($filecache, true), DEBUG_DEBUG);

		if (false === $filecache) {
			debug("Filecache could not be read.", DEBUG_DEFAULT);
		} else {
			foreach ($filecache as $filename => $file) {
				debug("##################################################", DEBUG_DEBUG);
				debug("\$filename = ".$filename, DEBUG_DEBUG);
				debug("\$file[path] = ".$file["path"], DEBUG_DEBUG);
				debug("\$file[storage] = ".var_export($file["storage"], true), DEBUG_DEBUG);
				debug("\$file[encrypted] = ".var_export($file["encrypted"], true), DEBUG_DEBUG);

				// check if this is a file in a user folder
				if ("1" !== $file["storage"]) {
					// get the filename behind the colon
					$filename = substr($filename, strpos($filename, ":")+1);

					// check if there is a file with the same path but in the root folder
					if (array_key_exists("1".":".$filename, $filecache)) {
						$duplicate = $filecache["1".":".$filename];

						// WARNING: using addslashes() to escape a string is not secure for SQL queries,
						// unfortunately correct ways like mysqli_real_escape_string() require an active databse connection
						debug("DELETE FROM ".DBTABLEPREFIX."filecache WHERE storage = ".$duplicate["storage"]." AND path = '".addslashes($duplicate["path"])."';", DEBUG_DEFAULT);
					}
				}

				debug("##################################################", DEBUG_DEBUG);
			}
		}

		return $result;
	}

	exit(main($argv));


# nextcloud-tools

**ARCHIVED: This original repository has been archived and is unmaintained. Please find the maintained fork of the original maintainer at [nextcloud/encryption-recovery-tools](https://github.com/nextcloud/encryption-recovery-tools).**

The **nextcloud-tools** have been developed by [SysEleven](https://syseleven.de) to debug the encryption and signature methods executed by the default encryption module of Nextcloud. The provided scripts may be helpful for other Nextcloud users and developers to debug problems or restore files.

## Rescue Tooling

Rescue tooling is located in the `./rescue/` subfolder.

### decrypt-all-files.php

This script can save your precious files in cases where you encrypted them with the Nextcloud Server Side Encryption and still have access to the data directory and the Nextcloud configuration file ("config/config.php"). This script is able to decrypt locally stored files within the data directory. It supports master-key encrypted files, user-key encrypted files and can also use a rescue key (if enabled) and the public sharing key if files had been publicly shared.

**Update 2023-01-23:** The `decrypt-all-files.php` script now also tries to recover files that broke during the execution of `./occ encryption:encrypt-all`.

**Update 2022-12-28:** The `decrypt-all-files.php` script now supports the new binary encoding that was introduced with the Nextcloud 25 release. Furthermore, the code has been reworked and smaller improvements have been added.

**Update 2022-07-14:** The `decrypt-all-files.php` script now includes a PHP-only implementation of RC4 so that files can be decrypted even when the legacy support of OpenSSL v3 is not enabled. You can enable the OpenSSL v3 legacy support by adding the following configuration to the end of your `openssl.cnf` file that [MartB](https://github.com/MartB) has provided:

```
[provider_sect]
default = default_sect
legacy  = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
```

**Update 2022-07-14:** [@fastlorenzo](https://github.com/fastlorenzo) has provided a patch so that the `decrypt-all-files.php` script now supports even older encrypted files.

**Update 2021-07-05:** The `decrypt-all-files.php` script now has improved support for external storages as well as the updated encrypted JSON key format that is introduced with the Nextcloud 21 release. It also supports the decryption of single files and a failed encryption can be resumed by starting the script again.

**Update 2020-08-29:** The `decrypt-all-files.php` script now has basic support for external storages as well as the encrypted JSON key format that is introduced with the Nextcloud 20 release.

#### Configuration

##### Nextcloud Definitions

The Nextcloud definitions are values that you have to copy from the Nextcloud configuration file (`"config/config.php"`). The names of the values are equal to the ones found in the Nextcloud configuration file.

* **`DATADIRECTORY`** - this is the location of the data directory of your Nextcloud instance, if you copied or moved your data directory then you have to set this value accordingly, this directory has to exist and contain the typical file structure of Nextcloud
* **`INSTANCEID`** - this is a value from the Nextcloud configuration file, there does not seem to be another way to retrieve this value
* **`SECRET`** - this is a value from the Nextcloud configuration file, there does not seem to be another way to retrieve this value

##### Custom Definitions

The custom definitions define how the `decrypt-all-files.php` script works internally. These are the supported configuration values:

* **`RECOVERY_PASSWORD`** - this is the password for the recovery key, you can set this value if you activated the recovery feature of your Nextcloud instance, leave this value empty if you did not acticate the recovery feature of your Nextcloud instance
* **`USER_PASSWORDS`** - these are the passwords for the user keys, you have to set these values if you disabled the master key encryption of your Nextcloud instance, you do not have to set these values if you did not disable the master key encryption of your Nextcloud instance, each value represents a (username, password) pair and you can set as many pairs as necessary
* **`EXTERNAL_STORAGES`** - these are the mount paths of external folders, you have to set these values if you used external storages within your Nextcloud instance, each value represents an (external storage, mount path) pair and you can set as many pairs as necessary, the external storage name has to be written as found in the `DATADIRECTORY/files_encryption/keys/files/` folder, if the external storage belongs to a specific user then the name has to contain the username followed by a slash followed by the external storage name as found in the `DATADIRECTORY/$username/files_encryption/keys/files/` folder, the external storage has to be mounted by yourself and the corresponding mount path has to be set
* **`SUPPORT_MISSING_HEADERS`** - this is a value that tells the script if you have encrypted files without headers, this configuration is only needed if you have data from a VERY old OwnCloud/Nextcloud instance, you probably should not set this value as it will break unencrypted files that may live alongside your encrypted files

#### Execution

To execute the script you have to call it in the following way:

```
./decrypt-all-files.php <targetdir> [<sourcedir>|<sourcefile>]*
```

* **`<targetdir>`** - this is the target directory where the decrypted files get stored, the target directory has to already exist and should be empty as already-existing files will be skipped, make sure that there is enough space to store all decrypted files in the target directory
* **`<sourcedir>`** - this is the name of the source folder which shall be decrypted, the name of the source folder has to be either absolute or relative to the `DATADIRECTORY, if this parameter is not provided then all files in the data directory will be decrypted
* **`<sourcefile>`** - this is the name of the source file which shall be decrypted, the name of the source file has to be either absolute or relative to the `DATADIRECTORY`, if this parameter is not provided then all files in the data directory will be decrypted

The execution may take a lot of time, depending on the power of your computer and on the number and size of your files. Make sure that the script is able to run without interruption. As of now it does not have a resume feature. On servers you can achieve this by starting the script within a `screen` session.

Also, the script currently does **not** support the decryption of files in the trashbin that have been deleted from external storage as Nextcloud creates zero byte files when deleting such a file instead of copying over its actual content.

**Windows users:** This script heavily relies on pattern matching which assumes that forward slashes (`/`) are used as the path separators instead of backslashes (`/`). When providing paths to the script either in the configuration or through the command line then please make sure to replace all backslashes with forward slashes.

## Debug Tooling

**The debug tooling only supports older versions of the Nextcloud Server Side Encryption. Use the [rescue tooling](#rescue-tooling) instead which is kept up-to-date.**

Debug tooling is located in the `./debug/` subfolder.

### check-signature.php

The `check-signature.php` script contains a re-implementation of Nextcloud's signature checking process. It supports different types of private keys - including master keys, public sharing keys, recovery keys and user keys. Furthermore, it supports different types of files - including regular files, version files, trashed files and trashed version files.

**Update:** Nextcloud now finally supports the correction of version information through the `./occ encryption:fix-encrypted-version` command which has been ported over from OwnCloud. Using the built-in command will be easier to use to fix broken file signatures.

#### Preparation

As the `check-signature.php` script does not implement database accesses, the necessary Nextcloud database tables have to be provided in the form of well-structured CSV files. These files can be exported directly from the database.

##### MariaDB/MySQL

To export the necessary CSV files from MariaDB/MySQL you have to connect to the correct database: `sudo mysql -D <dbname>`

Then you can execute the export:

```
SELECT storage, path, encrypted FROM oc_filecache INTO OUTFILE '/var/lib/mysql-files/filecache.csv' FIELDS ESCAPED BY '' TERMINATED BY ',' LINES TERMINATED BY '\n';

SELECT numeric_id, id FROM oc_storages INTO OUTFILE '/var/lib/mysql-files/storages.csv' FIELDS ESCAPED BY '' TERMINATED BY ',' LINES TERMINATED BY '\n';

QUIT;
```

You finally have to move the CSV files to their target location:

```
sudo mv /var/lib/mysql-files/filecache.csv /tmp/

sudo mv /var/lib/mysql-files/storages.csv /tmp/
```

##### PostgreSQL

To export the necessary CSV files from PostgreSQL you have to connect to the correct database: `sudo -u <dbuser> psql -d <dbname>`

Then you can execute the export:

```
\COPY (SELECT storage, path, encrypted FROM oc_filecache) TO '/tmp/filecache.csv' WITH CSV DELIMITER ',';

\COPY (SELECT numeric_id, id FROM oc_storages) TO '/tmp/storages.csv' WITH CSV DELIMITER ',';

\q
```

#### Configuration

The `check-signature.php` script needs some configuration values to be set.

##### Nextcloud Definitions

The Nextcloud definitions are values that you have to copy from the Nextcloud configuration file (`"config/config.php"`). The names of the values are equal to the ones found in the Nextcloud configuration file.

##### Custom Definitions

The custom definitions define how the `check-signature.php` script works internally. These are the supported configuration values:

* **`DEBUGLEVEL`** - defines how much output is generated by the script. `DEBUG_DEFAULT` only outputs negative results. `DEBUG_INFO` outputs negative and positive results. `DEBUG_DEBUG` outputs negative and positive results as well as details about the internal state of the script. (*Use `DEBUG_DEBUG` with caution as it can produce a lot of output.*)
* **`FILECACHE`** - defines the path of the CSV export of the `oc_filecache` table.
* **`FIXSIGNATURES`** - defines whether files with bad signatures shall be fixed. `FIX_NONE` disables this feature. `FIX_DATABASE` tries to generate SQL statements to fix the database entries of the files. `FIX_FILE` tries to rewrite the files with correct signatures. (*Use `FIX_FILE` with caution as it can break your files.*)
* **`KEYTYPE`** - defines which key type shall be used to decrypt file keys. `KEY_MASTER` activates the master key support. `KEY_PUBSHARE` activates the public sharing key support. `KEY_RECOVERY` activates the recovery key support. `KEY_USER` activates the user key support.
* **`MAXFILESIZE`** - defines the maximum size of handled files in bytes. Set the memory limit accordingly: `php -d memory_limit=<2 * MAXFILESIZE + sizeof(/tmp/filecache.txt) + sizeof(/tmp/storages.txt) + overhead> ./check-signature.php`
* **`MAXVERSION`** - defines up to which version number signatures shall be checked when `FIXSIGNATURE` is set to `FIX_DATABASE`.
* **`RECOVERY_PASSWORD`** - defines the password of the recovery key when the recovery key support is activated through `KEYTYPE` or when the signature of the recovery private key shall be checked.
* **`STORAGES`** - defines the path of the CSV export of the `oc_storages` table.
* **`USER_NAME`** - defines the name of the user key when the user key support is activated through `KEYTYPE`.
* **`USER_PASSWORD`** - defines the password of the user key when the user key support is activated through `KEYTYPE` or when the signature of the user private key of `USER_NAME` shall be checked.

##### User Password Definitions

The `check-signature.php` script supports to check the signature of user key files. In order to do this the scripts needs to have acces to the password of the user key. To provide the passwords for different users the corresponding `USER_PASSWORD_USERNAME` value can be set whereby `USERNAME` has to be replaced with the actual username.

#### Execution

The `check-signature.php` script supports two different ways of execution.

##### Check individual files

The `check-signature.php` script supports to check individual files. In order to do this the script has to be called with the names of the files that shall be checked. The files have to be referenced with their absolute path or with their path relative to the Nextcloud `datadirectory` folder.

##### Check the whole data directory

The `check-signature.php` scripts supports to check the whole Nextcloud data directory. In order to do this the script has to be called without additional parameters.

### decrypt-file.php

The `decrypt-file.php` script contains a re-implementation of Nextcloud's file decryption process. It supports different types of private keys - including master keys, public sharing keys, recovery keys and user keys. Furthermore, it supports different types of files - including regular files, version files, trashed files and trashed version files.

**Update:** Use the [`decrypt-all-files.php`](#decrypt-all-filesphp) script instead, which finally supports the decryption of single files as well, but is actively maintained.

#### Configuration

The `decrypt-file.php` script needs some configuration values to be set.

##### Nextcloud Definitions

The Nextcloud definitions are values that you have to copy from the Nextcloud configuration file (`"config/config.php"`). The names of the values are equal to the ones found in the Nextcloud configuration file.

##### Custom Definitions

The custom definitions define how the `decrypt-file.php` script works internally. These are the supported configuration values:

* **`DEBUGLEVEL`** - defines how much output is generated by the script. `DEBUG_DEFAULT` and `DEBUG_INFO` only output the decrypted file content and negative results. `DEBUG_DEBUG` outputs the decrypted file content and negative results as well as details about the internal state of the script. (*Use `DEBUG_DEBUG` with caution as it can produce a lot of output.*)
* **`KEYTYPE`** - defines which key type shall be used to decrypt file keys. `KEY_MASTER` activates the master key support. `KEY_PUBSHARE` activates the public sharing key support. `KEY_RECOVERY` activates the recovery key support. `KEY_USER` activates the user key support.
* **`RECOVERY_PASSWORD`** - defines the password of the recovery key when the recovery key support is activated through `KEYTYPE`.
* **`USER_NAME`** - defines the name of the user key when the user key support is activated through `KEYTYPE`.
* **`USER_PASSWORD`** - defines the password of the user key when the user key support is activated through `KEYTYPE`.

#### Execution

The `decrypt-file.php` script only supports to decrypt one individual file at a time. In order to do this the script has to be called with the name of the file that shall be decrypted. The file has to be referenced with its absolute path or with its path relative to the Nextcloud `datadirectory` folder.

The script outputs the decrypted file content to STDOUT so it is advised to pipe the output into a file.

### fix-duplicate.php

The `fix-signature.php` script checks the `oc_filecache` table for file duplicates and creates SQL statements to delete the duplicates. The problem this scripts tries to solve is that Nextcloud at some point in time added files to the `oc_filecache` table with two different entry structures:

1. `storage = 1` and `path = $username/$path`
2. `storage != 1` and `path = $path`

#### Preparation

As the `fix-duplicate.php` script does not implement database accesses, the necessary Nextcloud database tables have to be provided in the form of well-structured CSV files. These files can be exported directly from the database.

##### MariaDB/MySQL

To export the necessary CSV files from MariaDB/MySQL you have to connect to the correct database: `sudo mysql -D <dbname>`

Then you can execute the export:

```
SELECT storage, path, encrypted FROM oc_filecache INTO OUTFILE '/var/lib/mysql-files/filecache.csv' FIELDS ESCAPED BY '' TERMINATED BY ',' LINES TERMINATED BY '\n';

SELECT numeric_id, id FROM oc_storages INTO OUTFILE '/var/lib/mysql-files/storages.csv' FIELDS ESCAPED BY '' TERMINATED BY ',' LINES TERMINATED BY '\n';

QUIT;
```

You finally have to move the CSV files to their target location:

```
sudo mv /var/lib/mysql-files/filecache.csv /tmp/

sudo mv /var/lib/mysql-files/storages.csv /tmp/
```

##### PostgreSQL

To export the necessary CSV files from PostgreSQL you have to connect to the correct database: `sudo -u <dbuser> psql -d <dbname>`

Then you can execute the export:

```
\COPY (SELECT storage, path, encrypted FROM oc_filecache) TO '/tmp/filecache.csv' WITH CSV DELIMITER ',';

\COPY (SELECT numeric_id, id FROM oc_storages) TO '/tmp/storages.csv' WITH CSV DELIMITER ',';

\q
```

#### Configuration

The `fix-duplicate.php` script needs some configuration values to be set.

##### Nextcloud Definitions

The Nextcloud definitions are values that you have to copy from the Nextcloud configuration file (`"config/config.php"`). The names of the values are equal to the ones found in the Nextcloud configuration file.

##### Custom Definitions

The custom definitions define how the `fix-duplicate.php` script works internally. These are the supported configuration values:

* **`DEBUGLEVEL`** - defines how much output is generated by the script. `DEBUG_DEFAULT` and `DEBUG_INFO` only output positive and negative results. `DEBUG_DEBUG` outputs positive and negative results as well as details about the internal state of the script. (*Use `DEBUG_DEBUG` with caution as it can produce a lot of output.*)
* **`FILECACHE`** - defines the path of the CSV export of the `oc_filecache` table.
* **`STORAGES`** - defines the path of the CSV export of the `oc_storages` table.

#### Execution

The `fix-duplicate.php` script does not support any parameters.

The script outputs the result to STDOUT so it is advised to pipe the output into a file.

### inject-content.php

The `inject-content.php` script takes a filename, a known plaintext and a target plaintext and manipulates a server-side encrypted file so that it contains the target plaintext instead of the known plaintext.

#### Configuration

The `inject-content.php` script needs some configuration values to be set.

##### Nextcloud Definitions

The Nextcloud definitions are values that you have to copy from the Nextcloud configuration file (`"config/config.php"`). The names of the values are equal to the ones found in the Nextcloud configuration file.

##### Custom Definitions

The custom definitions define how the `inject-content.php` script works internally. These are the supported configuration values:

* **`DEBUGLEVEL`** - defines how much output is generated by the script. `DEBUG_DEFAULT` and `DEBUG_INFO` only output positive and negative results. `DEBUG_DEBUG` outputs positive and negative results as well as details about the internal state of the script. (*Use `DEBUG_DEBUG` with caution as it can produce a lot of output.*)
* **`MAXFILESIZE`** - defines the maximum size of handled files in bytes. Set the memory limit accordingly: `php -d memory_limit=<MAXFILESIZE + overhead> ./inject-content.php`

#### Execution

The `inject-content.php` script only supports to inject one individual file at a time. In order to do this the script has to be called with the name of the file that shall be injected. The file has to be referenced with its absolute path or with its path relative to the Nextcloud `datadirectory` folder.

Additionally, the old content has be provided as a hexadecimally encoded value as well as the new content which also has to be provided as a hexadecimally encoded value. Both values must have the same length and their payload must not exceed 16 bytes.

The script outputs the result to STDOUT so it is advised to pipe the output into a file.

### strip-signature.php

The `strip-signature.php` script takes a filename and manipulates a server-side encrypted file so that its content blocks do not contain message authentication codes anymore.

#### Configuration

The `strip-signature.php` script needs some configuration values to be set.

##### Nextcloud Definitions

The Nextcloud definitions are values that you have to copy from the Nextcloud configuration file (`"config/config.php"`). The names of the values are equal to the ones found in the Nextcloud configuration file.

##### Custom Definitions

The custom definitions define how the `strip-signature.php` script works internally. These are the supported configuration values:

* **`DEBUGLEVEL`** - defines how much output is generated by the script. `DEBUG_DEFAULT` and `DEBUG_INFO` only output positive and negative results. `DEBUG_DEBUG` outputs positive and negative results as well as details about the internal state of the script. (*Use `DEBUG_DEBUG` with caution as it can produce a lot of output.*)
* **`MAXFILESIZE`** - defines the maximum size of handled files in bytes. Set the memory limit accordingly: `php -d memory_limit=<MAXFILESIZE + overhead> ./strip-signature.php`

#### Execution

The `strip-signature.php` script only supports to strip one individual file at a time. In order to do this the script has to be called with the name of the file that shall be stripped. The file has to be referenced with its absolute path or with its path relative to the Nextcloud `datadirectory` folder.

The script outputs the result to STDOUT so it is advised to pipe the output into a file.

## Documentation

Documentation is located in the `./documentation/` subfolder.

### server-side-encryption.md

The document `server-side-encryption.md` contains the collected knowledge of [SysEleven](https://syseleven.de) about the file types and key types as well as the key pair generation, file encryption and file decryption processes of Nextcloud. It has become part of the official [Nextcloud Administration Manual](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/encryption_details.html).

### server-side-encryption.rst

The document `server-side-encryption.rst` contains the collected knowledge of [SysEleven](https://syseleven.de) about the file types and key types as well as the key pair generation, file encryption and file decryption processes of Nextcloud. This file contains the same information as `server-side-encryption.md` but uses the document syntax of the Nextcloud documentation CMS. It has become part of the official [Nextcloud Administration Manual](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/encryption_details.html).

# Changelog

## 1.2.10

### Fix Bug

- Fix the bug in `path_join()`.

## 1.2.9

### Fix Bug

- Fix the bug in `path_join()`.

## 1.2.8

### Fix Bug

- Fix the bug of importing error when using jupyter notebook.

## 1.2.7

### Fix Bug

- Fix the bug in RSA encryption that would raise error when using the OAEP padding mode.

## 1.2.6

### New Feature

- Support the key format of "PKCS#8" for RSA.
- Support the export format of "DER" for RSA.
- Add a new feature of `get_file_md5()` that can get the md5 of a file.
- Add a new feature in `SFTP` that can remove a remote file or directory.
- Add a new feature in `VaultSecretEngineKV1` that can create secret path.
- Add a new feature in `VaultSecretEngineKV2` that can create secret path.
- Add a new feature in `VaultSecretEngineKV2` that listing existing secret keys.
- Add a new feature that support [Cubbyhole](https://developer.hashicorp.com/vault/docs/secrets/cubbyhole) backend for vault.
- Add a new feature that join paths automatically depending on the OS type.

### Fix Bug

- Fix the bug in Vault API that would raise error (generating random seed) when the Python version is greater than 3.11.
- Fix the bug in `VaultSecretEngineKV1` that `read_secret()` fail to return secret due to dict type calling error.
- Fix the bug of docs of `get_wrapping_key()` in `VaultSecretEngineTransit` that it would return a string (not a dict) of public key if success.
- Fix the bug of uploading attachments in `SMTPAPI.send_email()` method.

### BREAKING CHANGE

- Deprecate the `rsa` library.
- Pass in the OS type of the remote server when instantiating `SFTP`.


## 1.2.5

### Small Change

- Would not establish SSH connection when creating an SFTP connection.
- Offer a default transferring progress bar for SFTP operations.


## 1.2.4

### New Feature

- Add the new feature of loading and saving `TOML` files.
- Support non-SSL connection to SMTP server.
- Support NOOP for SMTP email server.

### Small Change

- Delete path existence check in `SQLiteAPI`.
- Use `rich` to render the table instead of `prettytable`.

### Fix Bug

- Modify the logo url address in `generate_otp_secret()`


## 1.2.3

### Small Change

- Refactor `EmojiProgressBar`, which would not depend on the `rich` library anymore.


## 1.2.2

### New Feature

- Add a new misc feature `get_net_info()` that can detect the IP and MAC address of the machine.

### Small Change

- `load_image()` check if `path` is an url before test connection when the `path` is not exist locally.

### BREAKING CHANGE

- Deprecate `get_mac_address()` as it is only applicable to single network iterface card.


## 1.2.1

### New Feature

- Add a new feature of the progress bar with emojis status
- Add a new misc feature: `is_squence()`


## 1.2.0a3

- Will not raise an connection error when failing to connect to database, Change to set `is_connect=False`
- Add the parameter of `encoding` in `load_json()`, `save_json()`, `load_yaml()`, `save_yaml()` methods


## 1.2.0a2

### New Feature

- Add the new feature of `register` module


## 1.2.0a1

### New Feature

- 2FA method: TOTP, HOTP
- Image IO
- Database
  - SQLite database backend
  - Add new method `get_tables()` to `MySQLAPI`, which can get all tables' name in the database
  - Add new method `get_fields()` to `MySQLAPI`, which can get the information of all fields in the table
  - Add new method `delete_table()` to `MySQLAPI`,  which can delete the entire data table
- Runtime analysis
  - Add new feature `show_register_modules()` in `timer` module, which returns all names of the registered module in list
- File operation
  - Add new feature `remove()` in `file` module, which can remove a file, a directory or a symbolic link automatically
- Some miscellaneous features

### BREAKING CHANGE

- Delete the requirement of [hvac](https://github.com/hvac/hvac), and reimplement Vault APIs with HTTP requests. Supported secret engines:
  - KV v1
  - KV v2
  - TOTP
  - Transit (wait for testing)
- Deprecate the self-built version feature, change to use `parse_version()` in `misc` which follow the [latest version scheme in packaging](https://packaging.python.org/en/latest/specifications/version-specifiers/).

### Small Change

- Database
  - Change the structure of `table_config` in `create_table()` method in `MySQLAPI`
  - Add `exist_ok` arguments to `create_table()` method so that it will not raise an error when creating an existing table
- File operation
  - Replace `mkdir()` with `create()` in `file` module, the latter has the advantage of can create a file, a directory or a symbolic link automatically
  - Add support for symbolic links
  - Delete the requirement of [xmltodict](https://github.com/martinblech/xmltodict), and reimplement `load_xml()` and `save_xml()`
- Encryption and decryption
  - Force the `key_length` must be larger or equal to 2048 for safety resons
  - Allow AES-128, AES-192, and AES-256
- Update the tutorial
- Miscellaneous

### Fix Bug

- Fix the bug in `Logger()` which may return negative elapsed time due to the truncated error
- Fix the bug of raising error when loading JSON or YAML files with list-like data
- Fix the bug in RSA encryption and decryption that will raise error when `key_length` is not equal to 1024
- Fix the bug in `save_image()` which fail to save image in `base64` backend
- Fix the bug in `get_image_from_url()` which return the wrong base64 encoded result when `return_base64` is True
- Fix the bug in `verify_otp_code()` which will raise an error when using HOTP method
- Fix the bug in `send_email()` in `SMTPAPI` which will raise an error when has a normarl attachment (which size smaller or equals to `chunk_size`) but does not offer the `remote_server_config`


## 1.1.0.rc1 (first release)

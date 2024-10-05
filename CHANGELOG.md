# Changelog

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

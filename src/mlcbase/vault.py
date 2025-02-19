# Copyright 2024 MuLingCloud
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
MuLingCloud base module: API of HashiCorp Vault

Supported auth meothods:
- Token
- Username & Password

Supported secret engines: 
- KV v1
- KV v2
- Cubbyhole
- TOTP
- Transit

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import re
import json
import base64
import random
from pathlib import Path
from datetime import datetime
from typing import Optional, Union, List

import requests
import pyotp
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP

from .logger import Logger
from .conifg import ConfigDict
from .entrypt_aes import aes_encrypt_text, aes_decrypt_text
from .entrypt_rsa import rsa_encrypt_text
from .register import SECRET
from .misc import random_hex, is_dict, is_str, is_list, is_int, is_base64

PathLikeType = Union[str, Path]


@SECRET.register_module()
class VaultDuration:
    """This class is used to parse Vault duration string format

    Refer to https://developer.hashicorp.com/vault/docs/concepts/duration-format for more details.
    """
    duration_pattern = r"^(?P<integer>\d+)(\.)?(?P<fraction>\d+)?(?P<unit>[a-z]+)?$"
    support_units = ["ns", "us", "ms", "s", "m", "h", "d"]

    def __init__(self, duration: str):
        self.__pattern = re.compile(self.duration_pattern)
        
        if not self.__pattern.match(duration):
            raise ValueError(f"Invalid Vault duration format: {duration}")
        
        self.__match = self.__pattern.match(duration)

        if self.unit not in self.support_units:
            raise ValueError(f"Invalid Vault duration unit: {self.unit}")
        
    @property
    def integer(self) -> int:
        return int(self.__match.group("integer"))
    
    @property
    def fraction(self) -> float:
        fraction = self.__match.group("fraction")
        if fraction is not None:
            fraction = float(f"0.{fraction}")
        else:
            fraction = 0.0
        return fraction
    
    @property
    def value(self) -> float:
        return self.integer + self.fraction
    
    @property
    def unit(self) -> str:
        unit = self.__match.group("unit")
        if unit is None:
            unit = "s"
        return unit
    
    def to_seconds(self):
        if self.unit == "ns":
            return self.value / 1e9

        if self.unit == "us":
            return self.value / 1e6

        if self.unit == "ms":
            return self.value / 1e3

        if self.unit == "s":
            return self.value

        if self.unit == "m":
            return self.value * 60
        
        if self.unit == "h":
            return self.value * 60 * 60
        
        if self.unit == "d":
            return self.value * 60 * 60 * 24
        
    def __eq__(self, other: "VaultDuration") -> bool:
        if not isinstance(other, VaultDuration):
            raise TypeError(f"Unsupported operand type(s) for ==: '{type(self).__name__}' and '{type(other).__name__}'")
        
        return self.to_seconds() == other.to_seconds()
    
    def __ne__(self, other: "VaultDuration") -> bool:
        if not isinstance(other, VaultDuration):
            raise TypeError(f"Unsupported operand type(s) for !=: '{type(self).__name__}' and '{type(other).__name__}'")
        
        return self.to_seconds() != other.to_seconds()
    
    def __lt__(self, other: "VaultDuration") -> bool:
        if not isinstance(other, VaultDuration):
            raise TypeError(f"Unsupported operand type(s) for <: '{type(self).__name__}' and '{type(other).__name__}'")
        
        return self.to_seconds() < other.to_seconds()
    
    def __le__(self, other: "VaultDuration") -> bool:
        if not isinstance(other, VaultDuration):
            raise TypeError(f"Unsupported operand type(s) for <=: '{type(self).__name__}' and '{type(other).__name__}'")
        
        return self.to_seconds() <= other.to_seconds()
    
    def __gt__(self, other: "VaultDuration") -> bool:
        if not isinstance(other, VaultDuration):
            raise TypeError(f"Unsupported operand type(s) for >: '{type(self).__name__}' and '{type(other).__name__}'")
        
        return self.to_seconds() > other.to_seconds()
    
    def __ge__(self, other: "VaultDuration") -> bool:
        if not isinstance(other, VaultDuration):
            raise TypeError(f"Unsupported operand type(s) for >=: '{type(self).__name__}' and '{type(other).__name__}'")
        
        return self.to_seconds() >= other.to_seconds()
    
    def __str__(self) -> str:
        return f"{self.value}{self.unit}"


class _VaultHTTPAPI:
    def __init__(self, 
                 url: str, 
                 auth_cfg: Union[dict, ConfigDict],
                 prefix: str = "/v1/",
                 work_dir: Optional[PathLikeType] = None,
                 logger: Optional[Logger] = None,
                 quiet: bool = False):
        """Vault HTTP API
        Refer to https://developer.hashicorp.com/vault/api-docs for more details.

        Args:
            url (str)
            auth_cfg (Union[ConfigDict, dict]): authorization config.
            prefix (str, optional): currently all API routes prefixed with /v1/. Defaults to "/v1/".
            work_dir (Optional[PathLikeType], optional): will save the log file to "work_dir/log/" if 
                                                         work_dir is specified. Defaults to None.
            logger (Optional[Logger], optional): Defaults to None.
            quiet (bool, optional): whether the logger to run in quiet mode. Defaults to False.
        """
        self.work_dir = Path(work_dir) if work_dir is not None else None
        self.logger = self._set_logger(logger, quiet)

        assert prefix == "/v1/", "v1 is currently the only API version for HashiCorp Vault."
        self.support_auth_methods = ["token", "userpass"]
        
        url = url.rstrip('/') + prefix
        self._key_len = 24
        self._seed = random.randint(0, 2**32-1)
        self.is_auth, self.url, self.token = self.__authorize(url, auth_cfg)

    def __authorize(self, url: str, auth_cfg: Union[ConfigDict, dict]):
        auth_cfg = ConfigDict(auth_cfg)
        auth_method = auth_cfg.pop("method", "token")
        assert auth_method in self.support_auth_methods, f"unsupported auth method: {auth_method}"

        if auth_method == "token":
            token = auth_cfg.token
            res = requests.get(url+"auth/token/lookup-self", headers={"X-Vault-Token": token})
            if res.status_code == 200:
                is_auth = True
            else:
                self._log_error_response(__class__.__name__, res, "vault connect failed")
                is_auth = False
        
        if auth_method == "userpass":
            username = auth_cfg.username
            password = auth_cfg.password
            res = requests.post(url+f"auth/userpass/login/{username}", data={"password": password})
            if res.status_code == 200:
                is_auth = True
                token = res.json()["auth"]["client_token"]
            else:
                self._log_error_response(__class__.__name__, res, "vault connect failed")
                is_auth = False

        if not is_auth:
            url = None
            token = None
        else:
            url = aes_encrypt_text(url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_encrypt_text(token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))

        return is_auth, url, token
    
    def _log_error_response(self, module_name: str, response: requests.Response, log_text: str):
        res_dict = ConfigDict(response.json())
        errors = res_dict.errors
        warnings = res_dict.warnings
        if errors is not None:
            error_text = "".join(errors)
            self.logger.error(f"{module_name} - {log_text} [{response.status_code}]: {error_text}")
        if warnings is not None:
            warning_text = "".join(warnings)
            self.logger.error(f"{module_name} - {log_text} [{response.status_code}]: {warning_text}")
        
    def _set_logger(self, logger: Optional[Logger], quiet: bool):
        if logger is None:
            now_time = datetime.now().strftime('%Y%m%d-%H%M%S')
            logger = Logger()
            if self.work_dir is not None:
                logger.init_logger(save_path=self.work_dir/'log'/f'{now_time}.log')
            else:
                logger.init_logger()
        if quiet:
            logger.set_quiet()
        else:
            logger.set_activate()
        return logger
    

@SECRET.register_module()
class VaultSecretEngineKV1(_VaultHTTPAPI):
    """KV Secret Engine (version 1)
    Refer to https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1 for more details.

    Init:
        connecting with token:
        >>> kv1_engine = VaultSecretEngineKV1(
        >>>     url="http://127.0.0.1:8200", 
        >>>     auth_cfg=dict(method="token", token="TOKEN")
        >>> )

        connecting with username & password:
        >>> kv1_engine = VaultSecretEngineKV1(
        >>>     url="http://127.0.0.1:8200",
        >>>     auth_cfg=dict(method="userpass", username="username", password="password")
        >>> )
    """

    def create_secret_path(self, 
                           mount_path: str, 
                           path: str, 
                           secrets: Optional[Union[dict, ConfigDict]] = None, 
                           placeholder_name: str = "placeholder"):
        """create a secret path

        Args:
            mount_path (str)
            path (str)
            secrets (Optional[Union[dict, ConfigDict]]): secret to be saved while creating the secret path. Defaults to None.
            placeholder_name (str): the name placeholder secret, only be used when `secrets` is None. Defaults to "placeholder".

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if secrets is not None:
                if not is_dict(secrets):
                    self.logger.error(f"{__class__.__name__} - create secret path error: secrets must be a dict or ConfigDict if it is not None")
                    return False
            else:
                if placeholder_name is None:
                    self.logger.error(f"{__class__.__name__} - create secret path error: placeholder_name must be provided if secrets is None")
                secrets = {placeholder_name: random_hex(6)}

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))

            # check if path exists
            res = requests.get(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token, "list": "true"})
            if res.status_code == 200:
                self.logger.error(f"{__class__.__name__} - create secret path error: path '{mount_path}/{path}' already exists")
                return False
            
            # create secret path
            res = requests.post(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token}, data=secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "create secret path error")
                return False
        
        return False

    def read_secret(self, mount_path: str, path: str, key: Optional[str] = None):
        """read a secret from "mount_path/path"

        Args:
            mount_path (str)
            path (str)
            key (Optional[str], optional): if key is None, returns all secrets in dict from 
                                           "mount_path/path", which is the same as list_secret(). 
                                           Defaults to None.

        Returns:
            dict: return a dict if key is not specified
            str or int: return a str or int if key is specified
            None: return None if an error occured
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token})
            if res.status_code == 200:
                data = res.json()["data"]
                if key is None:
                    return data
                else:
                    if key in data.keys():
                        return data[key]
                    else:
                        self.logger.error(f"{__class__.__name__} - read secret error: key '{key}' not found")
                        return None
            else:
                self._log_error_response(__class__.__name__, res, "read secret error")
                return None
            
        return None
        
    def list_secret(self, mount_path: str, path: str):
        """list all scerets from "mount_path/path"

        Args:
            mount_path (str)
            path (str)

        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token, "list": "true"})
            if res.status_code == 200:
                data = res.json()["data"]
                return data
            else:
                self._log_error_response(__class__.__name__, res, "list secret error")
                return None
        
        return None
    
    def add_secret(self, mount_path: str, path: str, secrets: Union[dict, ConfigDict]):
        """add secrets to "mount_path/path"
        
        You do not need to specify all the subkeys of secrets, only the subkeys that need to be added, which is convenient.

        Args:
            mount_path (str)
            path (str)
            secrets (Union[dict, ConfigDict])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if not is_dict(secrets):
                self.logger.error(f"{__class__.__name__} - add secret error: secrets must be a dict or ConfigDict")
                return False
            if len(list(secrets.keys())) == 0:
                self.logger.error(f"{__class__.__name__} - add secret error: secrets must not be empty")
                return False
            
            exists_secrets = self.list_secret(mount_path, path)
            if exists_secrets is not None:
                for key in exists_secrets.keys():
                    if key in secrets.keys():
                        self.logger.error(f"{__class__.__name__} - add secret error: key '{key}' already exists")
                        return False
                    secrets[key] = exists_secrets[key]
            else:
                return False
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            secrets.update(exists_secrets)
            res = requests.post(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token}, data=secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "add secret error")
                return False
        
        return False
    
    def update_secret(self, mount_path: str, path: str, secrets: Union[dict, ConfigDict]):
        """update the existing secret in "mount_path/path"
        
        You do not need to specify all the subkeys of secrets, only the subkeys that need to be updated, which is convenient.

        Args:
            mount_path (str)
            path (str)
            secrets (Union[dict, ConfigDict])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if not is_dict(secrets):
                self.logger.error(f"{__class__.__name__} - update secret error: secrets must be a dict or ConfigDict")
                return False
            if len(list(secrets.keys())) == 0:
                self.logger.error(f"{__class__.__name__} - update secret error: secrets must not be empty")
                return False
            
            exists_secrets = self.list_secret(mount_path, path)
            if exists_secrets is not None:
                for key in secrets.keys():
                    if key not in exists_secrets.keys():
                        self.logger.error(f"{__class__.__name__} - update secret error: key '{key}' not found")
                        return False
                    exists_secrets[key] = secrets[key]
            else:
                return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token}, data=exists_secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "update secret error")
                return False
        
        return False
    
    def delete_secret(self, mount_path: str, path: str, key: Union[str, List[str]]):
        """delete the existing secret from "mount_path/path"

        Args:
            mount_path (str)
            path (str)
            key (Union[str, List[str]])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if is_str(key):
                key = [key]
            if not is_list(key):
                self.logger.error(f"{__class__.__name__} - delete secret error: key must be a str or list of str")
                return False
            if len(key) == 0:
                self.logger.error(f"{__class__.__name__} - delete secret error: key must not be empty")
                return False

            exists_secrets = self.list_secret(mount_path, path)
            if exists_secrets is not None:
                for k in key:
                    if k not in exists_secrets.keys():
                        self.logger.warning(f"{__class__.__name__} - delete secret error: key '{k}' not found")
                        return False
                    del exists_secrets[k]
            else:
                return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token}, data=exists_secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete secret error")
                return False
        
        return False
    
    def delete_secret_path(self, mount_path: str, path: str):
        """delete the entire secret path of "mount_path/path"

        Args:
            mount_path (str)
            path (str)

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.delete(url+f"{mount_path}/{path}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete secret path error")
                return False

        return False


@SECRET.register_module()
class VaultSecretEngineKV2(_VaultHTTPAPI):
    """KV Secret Engine (version 2)
    
    Refer to https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2 for more details.

    Init:
        connecting with token:
        >>> kv2_engine = VaultSecretEngineKV2(
        >>>     url="http://127.0.0.1:8200", 
        >>>     auth_cfg=dict(method="token", token="TOKEN")
        >>> )

        connecting with username & password:
        >>> kv2_engine = VaultSecretEngineKV2(
        >>>     url="http://127.0.0.1:8200",
        >>>     auth_cfg=dict(method="userpass", username="username", password="password")
        >>> )
    """

    def create_secret_path(self, 
                           mount_path: str, 
                           path: str, 
                           secrets: Optional[Union[dict, ConfigDict]] = None, 
                           placeholder_name: str = "placeholder"):
        """create a secret path

        Args:
            mount_path (str)
            path (str)
            secrets (Optional[Union[dict, ConfigDict]]): secret to be saved while creating the secret path. Defaults to None.
            placeholder_name (str): the name placeholder secret, only be used when `secrets` is None. Defaults to "placeholder".

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if secrets is not None:
                if not is_dict(secrets):
                    self.logger.error(f"{__class__.__name__} - create secret path error: secrets must be a dict or ConfigDict if it is not None")
                    return False
            else:
                if placeholder_name is None:
                    self.logger.error(f"{__class__.__name__} - create secret path error: placeholder_name must be provided if secrets is None")
                secrets = {placeholder_name: random_hex(6)}

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))

            # check if path exists
            res = requests.get(url+f"{mount_path}/metadata/{path}", headers={"X-Vault-Token": token, "list": "true"})
            if res.status_code == 200:
                self.logger.error(f"{__class__.__name__} - create secret path error: path '{mount_path}/{path}' already exists")
                return False
            
            # create secret path
            data = {"data": secrets}
            res = requests.post(url+f"{mount_path}/data/{path}", headers={"X-Vault-Token": token}, data=json.dumps(data))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "create secret path error")
                return False
        
        return False
    
    def set_engine_config(self, mount_path: str, cfg: Union[dict, ConfigDict]):
        """set the configuration of the secret engine

        Args:
            mount_path (str)
            cfg (Union[dict, ConfigDict])

        Returns:
            bool: return True if success, otherwise return False
        """
        support_params = ["max_versions", "cas_required", "delete_version_after"]
        if not is_dict:
            self.logger.error(f"{__class__.__name__} - set engine config error: cfg must be a dict or ConfigDict")
            return False
        for key in cfg.keys():
            if key not in support_params:
                self.logger.error(f"{__class__.__name__} - set engine config error: key '{key}' not support")
                return False
        
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/config", headers={"X-Vault-Token": token}, data=cfg)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "set engine config error")
                return False
        
        return False
    
    def read_engine_config(self, mount_path: str):
        """read the configuration of the secret engine

        Args:
            mount_path (str)

        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/config", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "read engine config error")
                return None
            
        return None
    
    def read_secret(self, mount_path: str, path: str, key: Optional[str] = None, version: Optional[int] = None):
        """read secret from "mount_path/path"

        Args:
            mount_path (str)
            path (str)
            key (Optional[str], optional): read a specific secret. if None, return all secrets in 
                                           "mount_path/path". Defaults to None.
            version (Optional[int], optional): read a specific version of secret. if None, return the 
                                               latest version of secret. Defaults to None.

        Returns:
            dict, dict: return two dicts corresponding to secret and metadata if success
            None: return None if fail
        """
        if self.is_auth:
            all_versions = self.get_all_secret_versions(mount_path, path)
            if all_versions is None:
                return None
            
            if version is not None:
                if str(version) not in all_versions.keys():
                    self.logger.error(f"{__class__.__name__} - read secret error: version '{version}' not found")
                    return None
                
                if all_versions[str(version)]["destroyed"]:
                    self.logger.error(f"{__class__.__name__} - read secret error: version '{version}' has "
                                      f"been permanently destroyed")
                    return None

                if all_versions[str(version)]["deleted"]:
                    self.logger.error(f"{__class__.__name__} - read secret error: version '{version}' has "
                                      f"been deleted, please undelete it first")
                    return None
            else:
                version = all_versions["current_version"]
                switch_current_version = False
                if all_versions[str(version)]["destroyed"]:
                    self.logger.warning(f"{__class__.__name__} - read secret warning: current version '{version}' "
                                        f"has been permanently destroyed, switching to another version...")
                    switch_current_version = True
                if all_versions[str(version)]["deleted"]:
                    self.logger.warning(f"{__class__.__name__} - read secret warning: current version '{version}' "
                                        f"has been deleted, switching to another version...")
                    switch_current_version = True
                
                if switch_current_version:
                    while True:
                        version -= 1
                        if str(version) not in all_versions.keys():
                            self.logger.error(f"{__class__.__name__} - read secret error: no available versions")
                            return None
                        
                        destroyed = all_versions[str(version)]["destroyed"]
                        deleted = all_versions[str(version)]["deleted"]
                        if not destroyed and not deleted:
                            self.logger.info(f"{__class__.__name__} - read secret info: switch to version '{version}'")
                            break

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/data/{path}?version={version}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                data = res.json()["data"]
                secret = data["data"]
                metadata = data["metadata"]
                if key is not None:
                    if key not in secret.keys():
                        self.logger.error(f"{__class__.__name__} - read secret error: key '{key}' not found")
                        return None
                    else:
                        secret = secret[key]
                return secret, metadata
            else:
                self._log_error_response(__class__.__name__, res, "read secret error")
                return None
            
        return None
    
    def read_secret_metadata(self, mount_path: str, path: str):
        """read the metadata of "mount_path/path"

        Args:
            mount_path (str)
            path (str)

        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/metadata/{path}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "read secret metadata error")
                return None
            
        return None
    
    def get_all_secret_versions(self, mount_path: str, path: str):
        """get all available secret versions in "mount_path/path"

        Args:
            mount_path (str)
            path (str)

        Returns:
            dict or None: return a dict if success, otherwise return None
            
        Reurns example:
            If the configuration of the secret engine is max_versions=3.
            
            If the secret engine has only recorded 2 versions since created, the "versions" returns would be:
            >>> versions = {"current_version": 2, 
            >>>             "2": {"destroyed": bool, "deleted": bool}, 
            >>>             "1": {"destroyed": bool, "deleted": bool}}
            
            The key "current_version" is the latest version number, and key "destroyed" represents if this version of
            secret has been permanently destroyed, and key "deleted" represents if it has been deleted.
            
            If the secret engine has recorded 5 versions since created, the "versions" returns would be:
            >>> versions = {"current_version": 5,
            >>>             "5": {"destroyed": bool, "deleted": bool},
            >>>             "4": {"destroyed": bool, "deleted": bool},
            >>>             "3": {"destroyed": bool, "deleted": bool}}
        """
        if self.is_auth:
            secret_metadata = self.read_secret_metadata(mount_path, path)
            if secret_metadata is None:
                return None
            
            versions_meta = secret_metadata["versions"]
            versions = {"current_version": secret_metadata["current_version"]}
            for version in versions_meta.keys():
                destroyed = versions_meta[version]["destroyed"]
                deleted = versions_meta[version]["deletion_time"] != ""
                versions[version] = {"destroyed": destroyed, "deleted": deleted}
            
            return versions
        
        return None
    
    def add_secret(self, 
                   mount_path: str, 
                   path: str, 
                   secrets: Union[dict, ConfigDict], 
                   options: Union[dict, ConfigDict] = None,
                   version: Optional[int] = None):
        """add secrets to "mount_path/path"
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#options for more details about options.
        
        You do not need to specify all the subkeys of secrets, only the subkeys that need to be added, which is convenient.

        Args:
            mount_path (str)
            path (str)
            secrets (Union[dict, ConfigDict])
            options (Union[dict, ConfigDict], optional): Defaults to None.
            version (Optional[int], optional): add secrets based on a specific version. if None, based on 
                                               the latest version. Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if not is_dict(secrets):
                self.logger.error(f"{__class__.__name__} - add secret error: secrets must be a dict or ConfigDict")
                return False
            if len(list(secrets.keys())) == 0:
                self.logger.error(f"{__class__.__name__} - add secret error: secrets must not be empty")
                return False
            
            exists_secrets = self.read_secret(mount_path, path, version=version)
            if exists_secrets is not None:
                exists_secrets = exists_secrets[0]
                for key in exists_secrets.keys():
                    if key in secrets.keys():
                        self.logger.error(f"{__class__.__name__} - add secret error: key '{key}' already exists")
                        return False
                    secrets[key] = exists_secrets[key]
            else:
                return False
            
            if options is not None:
                if not is_dict(options):
                    self.logger.error(f"{__class__.__name__} - add secret error: options must be a dict or ConfigDict")
                    return False
                data = dict(options=options, data=secrets)
            else:
                data = dict(data=secrets)
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/data/{path}", headers={"X-Vault-Token": token}, data=json.dumps(data))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "add secret error")
                return False
            
        return False
    
    def update_secret(self,
                      mount_path: str, 
                      path: str,
                      secrets: Union[dict, ConfigDict],
                      options: Union[dict, ConfigDict] = None,
                      version: Optional[int] = None):
        """update secrets in "mount_path/path"
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#options for more details about options.
        
        You do not need to specify all the subkeys of secrets, only the subkeys that need to be updated, which is very
        similar to the "Patch secret" feature that offically supported.

        Args:
            mount_path (str)
            path (str)
            secrets (Union[dict, ConfigDict])
            options (Union[dict, ConfigDict], optional): Defaults to None.
            version (Optional[int], optional): update secrets in a specific version. if None, update the latest version.
                                               Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if not is_dict(secrets):
                self.logger.error(f"{__class__.__name__} - update secret error: secrets must be a dict or ConfigDict")
                return False
            if len(list(secrets.keys())) == 0:
                self.logger.error(f"{__class__.__name__} - update secret error: secrets must not be empty")
                return False
            
            exists_secrets = self.read_secret(mount_path, path, version=version)
            if exists_secrets is not None:
                exists_secrets = exists_secrets[0]
                for key in secrets.keys():
                    if key not in exists_secrets.keys():
                        self.logger.error(f"{__class__.__name__} - update secret error: key '{key}' not found")
                        return False
                    exists_secrets[key] = secrets[key]
            else:
                return False
            
            if options is not None:
                if not is_dict(options):
                    self.logger.error(f"{__class__.__name__} - update secret error: options must be a dict or ConfigDict")
                    return False
                data = dict(options=options, data=exists_secrets)
            else:
                data = dict(data=exists_secrets)
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/data/{path}", headers={"X-Vault-Token": token}, data=json.dumps(data))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "update secret error")
                return False
            
        return False
        
    def read_secret_subkeys(self, mount_path: str, path: str, version: Optional[int] = None, depth: int = 0):
        """read subkeys of secrets in "mount_path/path"

        Args:
            mount_path (str)
            path (str)
            version (Optional[int], optional): read subkeys of a specific version. if None, read subkeys of 
                                               the latest version. Defaults to None.
            depth (int, optional): specify the depth of subkeys. if equals 0, means no limit. Defaults to 0.

        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            all_versions = self.get_all_secret_versions(mount_path, path)
            if all_versions is None:
                return None
            
            if version is not None:
                if not is_int(version):
                    self.logger.error(f"{__class__.__name__} - read secret subkeys error: version must be an int")
                    return None
                
                if str(version) not in all_versions.keys():
                    self.logger.error(f"{__class__.__name__} - read secret subkeys error: version '{version}' not found")
                    return None
            else:
                version = all_versions["current_version"]
            if all_versions[str(version)]["destroyed"]:
                self.logger.error(f"{__class__.__name__} - read secret subkeys error: version '{version}' "
                                  f"has been permanently destroyed")
                return None
            if all_versions[str(version)]["deleted"]:
                self.logger.error(f"{__class__.__name__} - read secret subkeys error: version '{version}' "
                                  f"has been deleted, please undelete it first")
                return None

            if not is_int(depth):
                self.logger.error(f"{__class__.__name__} - read secret subkeys error: depth must be an int")
                return None
            param = f"?version={version}&depth={depth}"

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/subkeys/{path}", headers={"X-Vault-Token": token}, params=param)
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]["subkeys"]
            else:
                self._log_error_response(__class__.__name__, res, "read secret subkeys error")
                return None

        return None
    
    def delete_secret(self, mount_path: str, path: str, version: Optional[Union[int, List[int]]] = None):
        """delete secretes from "mount_path/path"

        Args:
            mount_path (str)
            path (str)
            version (Optional[Union[int, List[int]]], optional): delete a specific version or a list of versions.
                                                                 if version is None, then delete the latest version. 
                                                                 Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            all_versions = self.get_all_secret_versions(mount_path, path)
            if all_versions is None:
                return False
            
            if version is not None:
                if not (is_int(version) or is_list(version)):
                    self.logger.error(f"{__class__.__name__} - delete secret error: version must be an int or a list of int")
                    return False
                
                if is_int(version):
                    version = [version]
            else:
                version = [all_versions["current_version"]]
                self.logger.info(f"{__class__.__name__} - delete secret error: deleting the latest version '{version[0]}' ...")
            for v in version:
                if not is_int(v):
                    self.logger.error(f"{__class__.__name__} - delete secret error: version '{v}' must be an int")
                    return False
                
                if str(v) not in all_versions.keys():
                    self.logger.error(f"{__class__.__name__} - delete secret error: version '{v}' not found")
                    return False
                
                destroyed = all_versions[str(v)]["destroyed"]
                if destroyed:
                    self.logger.error(f"{__class__.__name__} - delete secret error: version '{v}' is already destroyed")
                    return False
                
                deleted = all_versions[str(v)]["deleted"]
                if deleted:
                    self.logger.error(f"{__class__.__name__} - delete secret error: version '{v}' is already deleted")
                    return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/delete/{path}", 
                                headers={"X-Vault-Token": token}, 
                                data=json.dumps(dict(versions=version)))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete secret error")
                return False

        return False
    
    def undelete_secret(self, mount_path: str, path: str, version: Union[int, List[int]]):
        """undelete secrets in "mount_path/path"

        Args:
            mount_path (str)
            path (str)
            version (Union[int, List[int]])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            all_versions = self.get_all_secret_versions(mount_path, path)
            if all_versions is None:
                return False
            
            if not (is_int(version) or is_list(version)):
                self.logger.error(f"{__class__.__name__} - undelete secret error: version must be an int or a list of int")
                return False
            if is_int(version):
                version = [version]
                
            for v in version:
                if not is_int(v):
                    self.logger.error(f"{__class__.__name__} - undelete secret error: version '{v}' must be an int")
                    return False
                
                if str(v) not in all_versions.keys():
                    self.logger.error(f"{__class__.__name__} - undelete secret error: version '{v}' not found")
                    return False
                
                destroyed = all_versions[str(v)]["destroyed"]
                if destroyed:
                    self.logger.error(f"{__class__.__name__} - undelete secret error: version '{v}' is already "
                                      f"destroyed, cannot be undeleted")
                    return False
                
                deleted = all_versions[str(v)]["deleted"]
                if not deleted:
                    self.logger.error(f"{__class__.__name__} - undelete secret error: version '{v}' is already "
                                      f"undeleted, cannot be undeleted")
                    return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/undelete/{path}", 
                                headers={"X-Vault-Token": token}, 
                                data=json.dumps(dict(versions=version)))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "undelete secret error")
                return False

        return False
    
    def destroy_secret(self, mount_path: str, path: str, version: Union[int, List[int]]):
        """destroy secrets in "mount_path/path"

        Once the secret is destroyed, it cannot be recovered.

        Args:
            mount_path (str)
            path (str)
            version (Union[int, List[int]])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            all_versions = self.get_all_secret_versions(mount_path, path)
            if all_versions is None:
                return False
            
            if not (is_int(version) or is_list(version)):
                self.logger.error(f"{__class__.__name__} - destroy secret error: version must be an int or a list of int")
                return False
            if is_int(version):
                version = [version]
                
            for v in version:
                if not is_int(v):
                    self.logger.error(f"{__class__.__name__} - destroy secret error: version '{v}' must be an int")
                    return False
                
                if str(v) not in all_versions.keys():
                    self.logger.error(f"{__class__.__name__} - destroy secret error: version '{v}' not found")
                    return False
                
                destroyed = all_versions[str(v)]["destroyed"]
                if destroyed:
                    self.logger.warning(f"{__class__.__name__} - destroy secret error: version '{v}' is already destroyed")
                    return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.put(url+f"{mount_path}/destroy/{path}", 
                               headers={"X-Vault-Token": token}, 
                               data=json.dumps(dict(versions=version)))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "destroy secret error")
                return False
            
        return False
    
    def list_secret(self, mount_path: str, path: str, version: Optional[int] = None):
        """list all scerets from "mount_path/path"

        Args:
            mount_path (str)
            path (str)
            version (Optional[int], optional): list a specific version of secret. if None, return the 
                                               latest version of secret. Defaults to None.

        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            all_versions = self.get_all_secret_versions(mount_path, path)
            if all_versions is None:
                return None
            
            if version is not None:
                if str(version) not in all_versions.keys():
                    self.logger.error(f"{__class__.__name__} - list secret error: version '{version}' not found")
                    return None
                
                if all_versions[str(version)]["destroyed"]:
                    self.logger.error(f"{__class__.__name__} - list secret error: version '{version}' has "
                                      f"been permanently destroyed")
                    return None

                if all_versions[str(version)]["deleted"]:
                    self.logger.error(f"{__class__.__name__} - list secret error: version '{version}' has "
                                      f"been deleted, please undelete it first")
                    return None
            else:
                version = all_versions["current_version"]
                switch_current_version = False
                if all_versions[str(version)]["destroyed"]:
                    self.logger.warning(f"{__class__.__name__} - read secret warning: current version '{version}' "
                                        f"has been permanently destroyed, switching to another version...")
                    switch_current_version = True
                if all_versions[str(version)]["deleted"]:
                    self.logger.warning(f"{__class__.__name__} - read secret warning: current version '{version}' "
                                        f"has been deleted, switching to another version...")
                    switch_current_version = True
                
                if switch_current_version:
                    while True:
                        version -= 1
                        if str(version) not in all_versions.keys():
                            self.logger.error(f"{__class__.__name__} - read secret error: no available versions")
                            return None
                        
                        destroyed = all_versions[str(version)]["destroyed"]
                        deleted = all_versions[str(version)]["deleted"]
                        if not destroyed and not deleted:
                            self.logger.info(f"{__class__.__name__} - read secret info: switch to version '{version}'")
                            break
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/data/{path}?version={version}", headers={"X-Vault-Token": token, "list": "true"})
            if res.status_code == 200:
                data = res.json()["data"]
                return data["data"]
            else:
                self._log_error_response(__class__.__name__, res, "list secret error")
                return None
        
        return None
    
    def delete_secret_path(self, mount_path: str, path: str):
        """delete the entire secret path of "mount_path/path"
        
        To delete secret path for KV v2, you must have a policy granting you the delete capability 
        on this /metadata/ path.

        Args:
            mount_path (str)
            path (str)

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.delete(url+f"{mount_path}/metadata/{path}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete secret path error")
                return False
            
        return False
    

class VaultSecretEngineCubbyhole(_VaultHTTPAPI):
    """Cubbyhole Secret Engine

    The `cubbyhole` secrets engine is used to store arbitrary secrets within the configured physical 
    storage for Vault namespaced to a token. In `cubbyhole`, paths are scoped per token. No token can 
    access another token's cubbyhole (even root token). When the token expires, its cubbyhole is destroyed.

    Also unlike the `kv` secrets engine, because the cubbyhole's lifetime is linked to that of an 
    authentication token, there is no concept of a TTL or refresh interval for values contained in the 
    token's cubbyhole.

    Writing to a key in the `cubbyhole` secrets engine will completely replace the old value.
    
    Refer to https://developer.hashicorp.com/vault/api-docs/secret/cubbyhole for more details.

    Init:
        connecting with token:
        >>> totp_engine = VaultSecretEngineTOTP(
        >>>     url="http://127.0.0.1:8200", 
        >>>     auth_cfg=dict(method="token", token="TOKEN")
        >>> )

        connecting with username & password:
        >>> totp_engine = VaultSecretEngineTOTP(
        >>>     url="http://127.0.0.1:8200",
        >>>     auth_cfg=dict(method="userpass", username="username", password="password")
        >>> )
    """
    def create_secret_path(self, 
                           path: str, 
                           secrets: Optional[Union[dict, ConfigDict]] = None, 
                           placeholder_name: str = "placeholder"):
        """create a secret path

        Args:
            path (str)
            secrets (Optional[Union[dict, ConfigDict]]): secret to be saved while creating the secret path. Defaults to None.
            placeholder_name (str): the name placeholder secret, only be used when `secrets` is None. Defaults to "placeholder".

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if secrets is not None:
                if not is_dict(secrets):
                    self.logger.error(f"{__class__.__name__} - create secret path error: secrets must be a dict or ConfigDict if it is not None")
                    return False
            else:
                if placeholder_name is None:
                    self.logger.error(f"{__class__.__name__} - create secret path error: placeholder_name must be provided if secrets is None")
                secrets = {placeholder_name: random_hex(6)}

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))

            # check if path exists
            res = requests.get(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token, "list": "true"})
            if res.status_code == 200:
                self.logger.error(f"{__class__.__name__} - create secret path error: path 'cubbyhole/{path}' already exists")
                return False
            
            # create secret path
            res = requests.post(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token}, data=secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "create secret path error")
                return False
        
        return False

    def read_secret(self, path: str, key: Optional[str] = None):
        """read a secret from "cubbyhole/path"

        Args:
            path (str)
            key (Optional[str], optional): if key is None, returns all secrets in dict from 
                                           "cubbyhole/path", which is the same as list_secret(). 
                                           Defaults to None.

        Returns:
            dict: return a dict if key is not specified
            str or int: return a str or int if key is specified
            None: return None if an error occured
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token})
            if res.status_code == 200:
                data = res.json()["data"]
                if key is None:
                    return data
                else:
                    if key in data.keys():
                        return data[key]
                    else:
                        self.logger.error(f"{__class__.__name__} - read secret error: key '{key}' not found")
                        return None
            else:
                self._log_error_response(__class__.__name__, res, "read secret error")
                return None
            
        return None
    
    def list_secret(self, path: str):
        """list all scerets from "cubbyhole/path"

        Args:
            path (str)

        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token, "list": "true"})
            if res.status_code == 200:
                data = res.json()["data"]
                return data
            else:
                self._log_error_response(__class__.__name__, res, "list secret error")
                return None
        
        return None

    def add_secret(self, path: str, secrets: Union[dict, ConfigDict]):
        """add secrets to "cubbyhole/path"
        
        You do not need to specify all the subkeys of secrets, only the subkeys that need to be added, which is convenient.

        Args:
            path (str)
            secrets (Union[dict, ConfigDict])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if not is_dict(secrets):
                self.logger.error(f"{__class__.__name__} - add secret error: secrets must be a dict or ConfigDict")
                return False
            if len(list(secrets.keys())) == 0:
                self.logger.error(f"{__class__.__name__} - add secret error: secrets must not be empty")
                return False
            
            exists_secrets = self.list_secret(path)
            if exists_secrets is not None:
                for key in exists_secrets.keys():
                    if key in secrets.keys():
                        self.logger.error(f"{__class__.__name__} - add secret error: key '{key}' already exists")
                        return False
                    secrets[key] = exists_secrets[key]
            else:
                return False
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            secrets.update(exists_secrets)
            res = requests.post(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token}, data=secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "add secret error")
                return False
        
        return False

    def update_secret(self, path: str, secrets: Union[dict, ConfigDict]):
        """update the existing secret in "cubbyhole/path"
        
        You do not need to specify all the subkeys of secrets, only the subkeys that need to be updated, which is convenient.

        Args:
            path (str)
            secrets (Union[dict, ConfigDict])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if not is_dict(secrets):
                self.logger.error(f"{__class__.__name__} - update secret error: secrets must be a dict or ConfigDict")
                return False
            if len(list(secrets.keys())) == 0:
                self.logger.error(f"{__class__.__name__} - update secret error: secrets must not be empty")
                return False
            
            exists_secrets = self.list_secret(path)
            if exists_secrets is not None:
                for key in secrets.keys():
                    if key not in exists_secrets.keys():
                        self.logger.error(f"{__class__.__name__} - update secret error: key '{key}' not found")
                        return False
                    exists_secrets[key] = secrets[key]
            else:
                return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token}, data=exists_secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "update secret error")
                return False
        
        return False

    def delete_secret(self, path: str, key: Union[str, List[str]]):
        """delete the existing secret from "cubbyhole/path"

        Args:
            path (str)
            key (Union[str, List[str]])

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if is_str(key):
                key = [key]
            if not is_list(key):
                self.logger.error(f"{__class__.__name__} - delete secret error: key must be a str or list of str")
                return False
            if len(key) == 0:
                self.logger.error(f"{__class__.__name__} - delete secret error: key must not be empty")
                return False

            exists_secrets = self.list_secret(path)
            if exists_secrets is not None:
                for k in key:
                    if k not in exists_secrets.keys():
                        self.logger.warning(f"{__class__.__name__} - delete secret error: key '{k}' not found")
                        return False
                    del exists_secrets[k]
            else:
                return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token}, data=exists_secrets)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete secret error")
                return False
        
        return False

    def delete_secret_path(self, path: str):
        """delete the entire secret path of "cubbyhole/path"

        Args:
            path (str)

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.delete(url+f"cubbyhole/{path}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete secret path error")
                return False

        return False
    

@SECRET.register_module()
class VaultSecretEngineTOTP(_VaultHTTPAPI):
    """TOTP Secret Engine
    
    Refer to https://developer.hashicorp.com/vault/api-docs/secret/totp for more details.

    Init:
        connecting with token:
        >>> totp_engine = VaultSecretEngineTOTP(
        >>>     url="http://127.0.0.1:8200", 
        >>>     auth_cfg=dict(method="token", token="TOKEN")
        >>> )

        connecting with username & password:
        >>> totp_engine = VaultSecretEngineTOTP(
        >>>     url="http://127.0.0.1:8200",
        >>>     auth_cfg=dict(method="userpass", username="username", password="password")
        >>> )
    """
    
    def create_key(self, 
                   mount_path: str, 
                   name: str,
                   account_name: str,
                   exported: bool = True,
                   key_size: int = 20,
                   issuer: str = "MuLingCloud",
                   period: int = 30,
                   algorithm: str = "SHA1",
                   digits: int = 6,
                   skew: int = 1,
                   qr_size: int = 200,
                   qr_save_path: Optional[str] = None,
                   return_secret: bool = False,
                   return_qr_code: bool = True):
        """create a key in "mount_path/"
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/totp#create-key for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the key to create. This is specified as part of the URL.
            account_name (str): Specifies the name of the account associated with the key. Defaults to None.
            exported (bool, optional): Specifies if a QR code and url are returned upon generating a key. 
                                       Only used if generate is true. Defaults to True.
            key_size (int, optional): Specifies the size in bytes of the Vault generated key. Defaults to 20.
            issuer (str, optional): Specifies the name of the key's issuing organization. Defaults to MuLingCloud.
            period (int, optional): Specifies the length of time in seconds used to generate a counter for the 
                                    TOTP code calculation. Defaults to 30.
            algorithm (str, optional): Specifies the hashing algorithm used to generate the TOTP code. 
                                       Options include "SHA1", "SHA256" and "SHA512". Defaults to "SHA1".
            digits (int, optional): Specifies the number of digits in the generated TOTP code. This value can 
                                    be set to 6 or 8. Defaults to 6.
            skew (int, optional): Specifies the number of delay periods that are allowed when validating a 
                                  TOTP code. This value can be either 0 or 1. Defaults to 1.
            qr_size (int, optional): Specifies the pixel size of the square QR code when generating a new key. 
                                     Only used if exported is true. If this value is 0, a QR code will not be 
                                     returned. Defaults to 200.
            qr_save_path (Optional[str], optional): Specifies the path to save the QR code image which should 
                                                    be a .png file. Defaults to None.
            return_secret (bool, optional): Specifies if the secret should be returned. Defaults to False.
            return_qr_code (bool, optional): Specifies if the QR code should be returned. Defaults to True.
                                     
        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/keys?list=true", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                exist_keys = res.json()["data"]["keys"]
                if exist_keys is not None:
                    if name in exist_keys:
                        self.logger.error(f"{__class__.__name__} - create key error: key '{name}' already exists")
                        return None
                
            if algorithm not in ["SHA1", "SHA256", "SHA512"]:
                self.logger.error(f"{__class__.__name__} - create key error: algorithm must be one of "
                                  f"'SHA1', 'SHA256' or 'SHA512'")
                return None
            if digits not in [6, 8]:
                self.logger.error(f"{__class__.__name__} - create key error: digits must be one of 6 or 8")
                return None
            if skew not in [0, 1]:
                self.logger.error(f"{__class__.__name__} - create key error: skew must be one of 0 or 1")
                return None
            if qr_size < 0:
                self.logger.error(f"{__class__.__name__} - create key error: qr_size must be a positive integer")
                return None
            
            data = {"generate": True,
                    "issuer": issuer,
                    "account_name": account_name,
                    "exported": exported,
                    "key_size": key_size,
                    "period": period,
                    "algorithm": algorithm,
                    "digits": digits,
                    "skew": skew}
            if not exported:
                self.logger.warning(f"{__class__.__name__} - create key warning: exported is set to False, "
                                    f"it won't return a QR code or url")
                return_secret = False
                return_qr_code = False
            else:
                data["qr_size"] = qr_size
            
            res = requests.post(url+f"{mount_path}/keys/{name}", headers={"X-Vault-Token": token}, data=json.dumps(data))
            if res.status_code == 200 or res.status_code == 204:
                response_data = res.json()["data"]
                result = {"metadata": {"mount_path": mount_path, 
                                       "name": name,
                                       "exported": exported,
                                       "key_size": key_size,
                                       "issuer": issuer,
                                       "account_name": account_name,
                                       "period": period,
                                       "algorithm": algorithm,
                                       "digits": digits,
                                       "skew": skew,
                                       "qr_size": qr_size}}
                
                if return_secret:
                    url = response_data.get("url", None)
                    if url is not None:
                        _, _, params = self.__parse_totp_url(url)
                        secret = params["secret"]
                        result["secret"] = secret
                
                qr_code = response_data.get("barcode", None)
                if qr_code is not None and qr_save_path is not None:
                    qr_image = base64.b64decode(qr_code)
                    with open(qr_save_path, "wb") as f:
                        f.write(qr_image)
                    self.logger.info(f"{__class__.__name__} - QR code image is saved to {qr_save_path}")
                if return_qr_code:
                    result["qr_code"] = qr_code
                
                return result
            else:
                self._log_error_response(__class__.__name__, res, "create key error")
                return None
            
        return None
    
    def update_key(self, 
                   mount_path: str, 
                   name: str,
                   key: Optional[str] = None,
                   account_name: Optional[str] = None,
                   issuer: Optional[str] = None,
                   period: Optional[int] = None,
                   algorithm: Optional[str] = None,
                   digits: Optional[int] = None,
                   return_secret_key: bool = False):
        """update a key in "mount path/"

        Args:
            mount_path (str)
            name (str)
            key (Optional[str], optional): Specifies the root key used to generate a TOTP code. If None, it 
                                           will randomly generate a new secret key. Defaults to None.
            account_name (Optional[str], optional): Specifies the account_name if you want to change it, 
                                                    otherwise remain as None. Defaults to None.
            issuer (Optional[str], optional): Specifies the issuer if you want to change it, otherwise remain 
                                              as None. Defaults to None.
            period (Optional[int], optional): Specifies the period if you want to change it, otherwise remain 
                                              as None. Defaults to None.
            algorithm (Optional[str], optional): Specifies the algorithm if you want to change it, otherwise 
                                                 remain as None. Defaults to None.
            digits (Optional[int], optional): Specifies the digits if you want to change it, otherwise remain 
                                              as None. Defaults to None.
            return_secret_key (bool, optional): Specifies whether to return the secret key. Defaults to False.

        Returns:
            bool or str: return True if success and return_secret_key is False, return the secret key if success 
                         and return_secret_key is True, otherwise return False.
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if exist_keys is None:
                self.logger.error(f"{__class__.__name__} - update key error: key '{name}' not found")
                return False
            else:
                if name not in exist_keys:
                    self.logger.error(f"{__class__.__name__} - reaupdated key error: key '{name}' not found")
                    return False
            
            data = self.read_key(mount_path, name)
            if data is None:
                return False
            if key is None:
                key = pyotp.random_base32()

            totp_url = self.__generate_totp_url(account_name=data["account_name"] if account_name is None else account_name,
                                                issuer=data["issuer"] if issuer is None else issuer,
                                                algorithm=data["algorithm"] if algorithm is None else algorithm,
                                                digits=data["digits"] if digits is None else digits,
                                                period=data["period"] if period is None else period,
                                                secret=key)
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/keys/{name}", headers={"X-Vault-Token": token}, data=json.dumps({"url": totp_url}))
            if res.status_code == 200 or res.status_code == 204:
                if return_secret_key:
                    return key
                else:
                    return True
            else:
                self._log_error_response(__class__.__name__, res, "update key error")
                return False

    def read_key(self, mount_path: str, name: str):
        """queries the key definition in "mount path/"

        Args:
            mount_path (str)
            name (str)

        Returns:
            dict or None: return a dict if success, otherwise return None
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if exist_keys is None:
                self.logger.error(f"{__class__.__name__} - read key error: key '{name}' not found")
                return None
            else:
                if name not in exist_keys:
                    self.logger.error(f"{__class__.__name__} - read key error: key '{name}' not found")
                    return None
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/keys/{name}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "read key error")
                return None
        
        return None


    def list_key(self, mount_path: str):
        """list keys in "mount path/"

        Args:
            mount_path (str)

        Returns:
            list or None: return a list of available keys if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/keys?list=true", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]["keys"]
            else:
                self._log_error_response(__class__.__name__, res, "list key error")
                return None

        return None
    
    def delete_key(self, mount_path: str, name: str):
        """delete a key from "mount path/"

        Args:
            mount_path (str)
            name (str)

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if exist_keys is None:
                self.logger.error(f"{__class__.__name__} - delete key error: key '{name}' not found")
                return False
            else:
                if name not in exist_keys:
                    self.logger.error(f"{__class__.__name__} - delete key error: key '{name}' not found")
                    return False
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.delete(url+f"{mount_path}/keys/{name}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete key error")
                return False

        return False
    
    def generate_code(self, mount_path: str, name: str):
        """generate a new time-based one-time use password based on the named key

        Args:
            mount_path (str)
            name (str)

        Returns:
            str: return the generated code if success, otherwise return None
        """
        if self.is_auth:
            data = self.read_key(mount_path, name)
            if data is None:
                self.logger.error(f"{__class__.__name__} - generate code error: key '{name}' not found")
                return None
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/code/{name}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]["code"]
            else:
                self._log_error_response(__class__.__name__, res, "generate code error")
                return None
        
        return None
    
    def validate_code(self, mount_path: str, name: str, code: str):
        """validate a code

        Args:
            mount_path (str)
            name (str)
            code (str)

        Returns:
            bool: return True if the code matched, otherwise return False
        """
        if self.is_auth:
            data = self.read_key(mount_path, name)
            if data is None:
                self.logger.error(f"{__class__.__name__} - validate code error: key '{name}' not found")
                return None
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/code/{name}", headers={"X-Vault-Token": token}, data=json.dumps({"code": code}))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]["valid"]
            else:
                self._log_error_response(__class__.__name__, res, "validate code error")
                return False

        return False
    
    @staticmethod
    def __parse_totp_url(url: str, title: str = "otpauth://totp/"):
        url = url.replace(title, "")
        issuer = url.split(":")[0]
        account_name = url.split(":")[1].split("?")[0]
        params = url.split(":")[1].split("?")[1].split("&")
        params_dict = {}
        for param in params:
            key, value = param.split("=")
            params_dict[key] = value
        return issuer, account_name, params_dict
    
    def __generate_totp_url(self,
                            account_name: str, 
                            issuer: str, 
                            algorithm: str,
                            digits: int,
                            period: int,
                            secret: str,
                            title="otpauth://totp/"):
        if not is_str(account_name):
            self.logger.error(f"{__class__.__name__} - generate totp url error: account_name must be a string")
            return None
        if not is_str(issuer):
            self.logger.error(f"{__class__.__name__} - generate totp url error: issuer must be a string")
            return None
        if algorithm not in ["SHA1", "SHA256", "SHA512"]:
            self.logger.error(f"{__class__.__name__} - generate totp url error: algorithm must be one of "
                              f"'SHA1', 'SHA256' or 'SHA512'")
            return None
        if digits not in [6, 8]:
            self.logger.error(f"{__class__.__name__} - generate totp url error: digits must be one of 6 or 8")
            return None
        if not is_int(period):
            self.logger.error(f"{__class__.__name__} - generate totp url error: period must be an int")
            return None
        
        url = f"{title}{issuer}:{account_name}?algorithm={algorithm}&digits={digits}&issuer={issuer}" \
              f"&period={period}&secret={secret}"

        return url
    

@SECRET.register_module()
class VaultSecretEngineTransit(_VaultHTTPAPI):
    """Transit Secret Engine

    We have ignored the enterprise only key type "managed_key".
    Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit for more details.

    Init:
        connecting with token:
        >>> transit_engine = VaultSecretEngineTransit(
        >>>     url="http://127.0.0.1:8200", 
        >>>     auth_cfg=dict(method="token", token="TOKEN")
        >>> )

        connecting with username & password:
        >>> transit_engine = VaultSecretEngineTransit(
        >>>     url="http://127.0.0.1:8200",
        >>>     auth_cfg=dict(method="userpass", username="username", password="password")
        >>> )
    """
    
    KEY_TYPES = [
        "aes128-gcm96",       # AES-128 wrapped with GCM using a 96-bit nonce size AEAD 
                              # (symmetric, supports derivation and convergent encryption)
                              
        "aes256-gcm96",       # AES-256 wrapped with GCM using a 96-bit nonce size AEAD 
                              # (symmetric, supports derivation and convergent encryption, default)
                              
        "chacha20-poly1305",  # ChaCha20-Poly1305 AEAD (symmetric, supports derivation and convergent encryption)
        
        "ed25519",            # ED25519 (asymmetric, supports derivation). When using derivation, 
                              # a sign operation with the same context will derive the same key and signature; 
                              # this is a signing analogue to convergent encryption
                              
        "ecdsa-p256",         # ECDSA using the P-256 elliptic curve (asymmetric)
        "ecdsa-p384",         # ECDSA using the P-384 elliptic curve (asymmetric)
        "ecdsa-p521",         # ECDSA using the P-521 elliptic curve (asymmetric)
        
        "rsa-2048",           # RSA with bit size of 2048 (asymmetric)
        "rsa-3072",           # RSA with bit size of 3072 (asymmetric)
        "rsa-4096",           # RSA with bit size of 4096 (asymmetric)
        
        "hmac"                # HMAC (HMAC generation, verification)
    ]
    
    def create_key(self, 
                   mount_path: str, 
                   name: str,
                   convergent_encryption: bool = False,
                   derived: bool = False,
                   exportable: bool = False,
                   allow_plaintext_backup: bool = False,
                   key_type: str = "aes256-gcm96",
                   key_size: int = 0,
                   auto_rotate_period: str = "0"):
        """create a new named encryption key of the specified type

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to create. This is specified as part of the URL.
            convergent_encryption (bool, optional): If enabled, the key will support convergent encryption, 
                                                    where the same plaintext creates the same ciphertext. 
                                                    This requires derived to be set to `true`. When enabled, 
                                                    each encryption(/decryption/rewrap/datakey) operation will 
                                                    derive a `nonce` value rather than randomly generate it. 
                                                    Defaults to False.
            derived (bool, optional): Specifies if key derivation is to be used. If enabled, all encrypt/decrypt 
                                      requests to this named key must provide a context which is used for key derivation. 
                                      Defaults to False.
            exportable (bool, optional): Enables keys to be exportable. This allows for all the valid keys in the key 
                                         ring to be exported. Once set, this cannot be disabled. Defaults to False.
            allow_plaintext_backup (bool, optional): If set, enables taking backup of named key in the plaintext format. 
                                                     Once set, this cannot be disabled. Defaults to False.
            key_type (str, optional): Specifies the type of key to create. Defaults to "aes256-gcm96".
            key_size (int, optional): The key size in bytes for algorithms that allow variable key sizes. 
                                      Currently only applicable to HMAC, where it must be between 32 and 512 bytes. 
                                      Defaults to 0.
            auto_rotate_period (str, optional): The period at which this key should be rotated automatically. 
                                                Setting this to "0" (the default) will disable automatic key rotation. 
                                                This value cannot be shorter than one hour. Defaults to "0".

        Returns:
            bool: return True if success, otherwise return False
        """
        
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name in exist_keys:
                self.logger.error(f"{__class__.__name__} - create key error: key '{name}' already exists")
                return False

            payload = ConfigDict()
            
            if convergent_encryption:
                if not derived:
                    self.logger.error(f"{__class__.__name__} - create key error: when convergent_encryption is True,"
                                      f" it requires derived to be set to True")
                    return False
                payload["convergent_encryption"] = convergent_encryption
            
            if derived:
                payload["derived"] = derived
            
            if exportable:
                payload["exportable"] = exportable

            if allow_plaintext_backup:
                payload["allow_plaintext_backup"] = allow_plaintext_backup

            if key_type.lower() not in self.KEY_TYPES:
                self.logger.error(f"{__class__.__name__} - create key error: key_type must be one of {self.KEY_TYPES}")
                return False
            payload["type"] = key_type.lower()

            if key_size > 0:
                payload["key_size"] = key_size
            
            rotate_period = VaultDuration(auto_rotate_period)
            if rotate_period.value > 0:
                lower_period = VaultDuration("1h")
                if rotate_period < lower_period:
                    self.logger.error(f"{__class__.__name__} - create key error: The value of auto_rotate_period cannot be shorter than one hour")
                    return False
                payload["auto_rotate_period"] = auto_rotate_period
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/keys/{name}", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "create key error")
                return False
        
        return False
    
    # TODO: wait for testing
    def wrap_private_or_symmetric_key(self, 
                                      mount_path: str, 
                                      target_key: str,
                                      hash_method: str = "SHA256",
                                      encoding: str = "utf-8") -> str:
        """wrap a private or symmetric key

        This function is implemented following the BYOK instructions:
        https://developer.hashicorp.com/vault/docs/v1.17.x/secrets/transit#bring-your-own-key-byok

        Args:
            mount_path (str)
            target_key (str): the target key waiting for wrap.
            hash_method (str, optional): The hash function used for the RSA-OAEP step of creating the 
                                         ciphertext. Supported hash functions are: SHA1, SHA224, SHA256, 
                                         SHA384, and SHA512. Defaults to "SHA256".
            encoding (str, optional): Defaults to "utf-8".
        
        Returns:
            str: ciphertext used to import into Vault
            Ciphertext is a base64-encoded string that contains two values: 
            an ephemeral 256-bit AES key wrapped using the wrapping key returned 
            by Vault and the encryption of the import key material under the 
            provided AES key. The wrapped AES key should be the first 512 bytes 
            of the ciphertext, and the encrypted key material should be the 
            remaining bytes. If public_key is set, this field is not required. 
            See the BYOK (Bring your own key) section of the Transit secrets engine 
            documentation for more information on constructing the ciphertext. 
        """
        hash_method = hash_method.replace("-", "")
        assert hash_method in ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']
        
        # 1. Generate an ephemeral 256-bit AES key
        ephemeral_aes_key = random_hex(32, seed=random.randint(0, 2**32-1))

        # 2. Get transit wrapping key from Vault
        wrapping_key = self.get_wrapping_key(mount_path)

        # 3. Wrap the target key using the ephemeral AES key with AES-KWP
        wrapped_target_key = aes_encrypt_text(target_key, key=ephemeral_aes_key, mode=AES.MODE_ECB)

        # 4. Wrap the AES key under the Vault wrapping key
        key = RSA.import_key(wrapping_key.encode("utf-8"))
        if hash_method == "MD5":
            hash_func = MD5
        elif hash_method == "SHA1":
            hash_func = SHA1
        elif hash_method == "SHA224":
            hash_func = SHA224
        elif hash_method == "SHA256":
            hash_func = SHA256
        elif hash_method == "SHA384":
            hash_func = SHA384
        elif hash_method == "SHA512":
            hash_func = SHA512
        wrapped_aes_key = PKCS1_OAEP.new(key, hashAlgo=hash_func).encrypt(ephemeral_aes_key.encode(encoding))

        # 5. Append the wrapped target key to the wrapped AES key
        cipherbytes = wrapped_aes_key + wrapped_target_key

        # 6. Base64 encode the result
        ciphertext = base64.b64encode(cipherbytes)

        return ciphertext.decode(encoding)

    def import_key(self, 
                   mount_path: str,
                   name: str,
                   private_or_symmetric_key: str = "",
                   hash_function: str = "SHA256",
                   key_type: str = "aes256-gcm96",
                   public_key: str = "",
                   allow_rotation: bool = False,
                   derived: bool = False,
                   context: str = "",
                   exportable: bool = False,
                   allow_plaintext_backup: bool = False,
                   auto_rotate_period: str = "0",
                   encoding: str = "utf-8"):
        """import existing key material into a new transit-managed encryption key
        
        This supports one of two forms:
        - Private/Symmetric Key import, requiring the ciphertext, hash_function parameters be set 
          (and automatically deriving the public key), or
        - Public Key-only import, restricting the operations that can be done with this key, and 
          requiring only the public_key parameter.
          
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key for more details

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to create. This is specified as part of the URL.
            private_or_symmetric_key (str, optional): A plaintext private or symmetric key to be imported. 
                                                      If public_key is set, this field is not required. 
                                                      Defaults to "".
            hash_function (str, optional): The hash function used for the RSA-OAEP step of creating the 
                                           ciphertext. Supported hash functions are: SHA1, SHA224, SHA256, 
                                           SHA384, and SHA512. Defaults to "SHA256".
            key_type (str, optional): Specifies the type of key to create. Defaults to "aes256-gcm96".
            public_key (str, optional): A plaintext PEM public key to be imported. This limits the operations 
                                        available under this key to verification and encryption, depending 
                                        on the key type and algorithm, as no private key is available. 
                                        Defaults to "".
            allow_rotation (bool, optional): If set, the imported key can be rotated within Vault by using 
                                             the rotate endpoint. Defaults to False.
            derived (bool, optional): Specifies if key derivation is to be used. If enabled, all encrypt/decrypt 
                                      requests to this named key must provide a context which is used for key 
                                      derivation. Defaults to False.
            context (str, optional): A base64-encoded string providing a context for key derivation. Required 
                                     if derived is set to true. Defaults to "".
            exportable (bool, optional): Enables keys to be exportable. This allows for all the valid keys in 
                                         the key ring to be exported. Once set, this cannot be disabled. Defaults 
                                         to False.
            allow_plaintext_backup (bool, optional): If set, enables taking backup of named key in the plaintext 
                                                     format. Once set, this cannot be disabled. Defaults to False.
            auto_rotate_period (str, optional): The period at which this key should be rotated automatically. 
                                                Setting this to "0" (the default) will disable automatic key 
                                                rotation. This value cannot be shorter than one hour. Defaults to "0".
            encoding (str, optional): Defaults to "utf-8".

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name in exist_keys:
                self.logger.error(f"{__class__.__name__} - import key error: key '{name}' already exists")
                return False
            
            payload = ConfigDict()
            
            if key_type.lower() not in self.KEY_TYPES:
                self.logger.error(f"{__class__.__name__} - import key error: key_type must be one of {self.KEY_TYPES}")
                return False
            payload["type"] = key_type.lower()
            
            if public_key != "":
                payload["public_key"] = public_key
            else:
                if private_or_symmetric_key == "":
                    self.logger.error(f"{__class__.__name__} - import key error: private_or_symmetric_key cannot be empty when public_key is empty")
                    return False
                
            if private_or_symmetric_key != "":
                ciphertext = self.wrap_private_or_symmetric_key(mount_path=mount_path, 
                                                                target_key=private_or_symmetric_key, 
                                                                hash_method=hash_function, 
                                                                encoding=encoding)
                payload["ciphertext"] = ciphertext
            
            if payload.ciphertext is not None:
                support_hash_function = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]
                hash_function = hash_function.replace("-", "")
                if hash_function not in support_hash_function:
                    self.logger.error(f"{__class__.__name__} - import key error: hash_function must be one of {support_hash_function}")
                    return False
                payload["hash_function"] = hash_function
                
            if allow_rotation:
                payload["allow_rotation"] = allow_rotation
                
            if derived:
                if context == "":
                    self.logger.error(f"{__class__.__name__} - import key error: context cannot be empty when derived is true")
                    return False
                if not is_base64(context):
                    self.logger.error(f"{__class__.__name__} - import key error: context must be base64 encoded")
                    return False
                payload["derived"] = derived
                payload["context"] = context
                
            if exportable:
                payload["exportable"] = exportable
                
            if allow_plaintext_backup:
                payload["allow_plaintext_backup"] = allow_plaintext_backup
            
            rotate_period = VaultDuration(auto_rotate_period)
            if rotate_period.value > 0:
                lower_period = VaultDuration("1h")
                if rotate_period < lower_period:
                    self.logger.error(f"{__class__.__name__} - import key error: The value of auto_rotate_period cannot be shorter than one hour")
                    return False
                payload["auto_rotate_period"] = auto_rotate_period
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/keys/{name}/import", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "import key error")
                return False
        
        return False

    def import_key_version(self, 
                           mount_path: str,
                           name: str,
                           ciphertext: str,
                           hash_function: str = "SHA256",
                           public_key: str = "",
                           version: Optional[int] = None):
        """import new key material into an existing imported key
        
        Notably, using this method, a private key matching a public key can be imported at a later date.
        
        Note: Keys whose material was generated by Vault do not support importing key material. 
              Only keys that were previously imported into Vault can import new key material from 
              an external source.

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#import-key-version for more details

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to create. This is specified as part of the URL.
            ciphertext (str): A base64-encoded string that contains two values: an ephemeral 256-bit AES key 
                              wrapped using the wrapping key returned by Vault and the encryption of the import 
                              key material under the provided AES key. The wrapped AES key should be the first 512 
                              bytes of the ciphertext, and the encrypted key material should be the remaining bytes. 
                              See the BYOK (Bring your own key) section of the Transit secrets engine documentation 
                              for more information on constructing the ciphertext.
            hash_function (str, optional): The hash function used for the RSA-OAEP step of creating the 
                                           ciphertext. Supported hash functions are: SHA1, SHA224, SHA256, 
                                           SHA384, and SHA512. Defaults to "SHA256".
            public_key (str, optional): A plaintext PEM public key to be imported. This limits the operations available 
                                        under this key to verification and encryption, depending on the key type and 
                                        algorithm, as no private key is available. Defaults to "".
            version (Optional[int], optional): Key version to be updated, if left empty, a new version will be created 
                                               unless a private key is specified and the 'Latest' key is missing a 
                                               private key. Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - import key version error: key '{name}' not found")
                return False
            
            payload = ConfigDict()
            
            if not is_base64(ciphertext):
                self.logger.error(f"{__class__.__name__} - import key version error: ciphertext must be base64 encoded")
                return False
            payload["ciphertext"] = ciphertext
            
            support_hash_function = ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]
            if hash_function not in support_hash_function:
                self.logger.error(f"{__class__.__name__} - import key version error: hash_function must be one of {support_hash_function}")
                return False
            payload["hash_function"] = hash_function
            
            if public_key != "":
                payload["public_key"] = public_key
                
            if version is not None:
                if not is_int(version):
                    self.logger.error(f"{__class__.__name__} - import key version error: version must be an integer")
                    return False
                payload["version"] = version
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/keys/{name}/import_version", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "import key version error")
                return False
            
        return False

    def get_wrapping_key(self, mount_path: str):
        """retrieve the wrapping key to use for importing keys. 
        
        The returned key will be a 4096-bit RSA public key.

        Args:
            mount_path (str)

        Returns:
            str or None: return str if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/wrapping_key", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]["public_key"]
            else:
                self._log_error_response(__class__.__name__, res, "get wrapping key error")
                return False
            
        
        return None

    def read_key(self, mount_path: str, name: str):
        """read the information about a named encryption key

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#read-key for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to read.

        Returns:
            dict or None: return the information about the key in dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/keys/{name}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "read key error")
                return None
        
        return None

    def list_key(self, mount_path: str):
        """list existing key names in "mount_path/"

        Args:
            mount_path (str)

        Returns:
            list or None: return a list of key names if success, otherwise return None
        """
        if self.is_auth:
            # check if the mount_path exists
            cache_config = self.read_transit_cache_config(mount_path)
            if cache_config is None:
                return None
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/keys?list=true", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]["keys"]
            elif res.status_code == 404:
                return []
            else:
                self._log_error_response(__class__.__name__, res, "list key error")
                return None
        
        return None

    def delete_key(self, mount_path: str, name: str):
        """delete key

        Args:
            mount_path (str)
            name (str)

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.delete(url+f"{mount_path}/keys/{name}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "delete key error")
                return False
            
        return False
    
    def update_key_config(self, 
                          mount_path: str,
                          name: str,
                          min_decryption_version: int = 0,
                          min_encryption_version: int = 0,
                          deletion_allowed: bool = False,
                          exportable: bool = False,
                          allow_plaintext_backup: bool = False,
                          auto_rotate_period: str = ""):
        """tuning configuration values for a given key

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#update-key-configuration for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the key to update
            min_decryption_version (int, optional): Specifies the minimum version of ciphertext allowed to be decrypted. 
                                                    Adjusting this as part of a key rotation policy can prevent old 
                                                    copies of ciphertext from being decrypted, should they fall into the 
                                                    wrong hands. For signatures, this value controls the minimum version 
                                                    of signature that can be verified against. For HMACs, this controls 
                                                    the minimum version of a key allowed to be used as the key for 
                                                    verification. Defaults to 0.
            min_encryption_version (int, optional): Specifies the minimum version of the key that can be used to encrypt 
                                                    plaintext, sign payloads, or generate HMACs. Must be 0 (which will use 
                                                    the latest version) or a value greater or equal to min_decryption_version. 
                                                    Defaults to 0.
            deletion_allowed (bool, optional): Specifies if the key is allowed to be deleted. Defaults to False.
            exportable (bool, optional): Enables keys to be exportable. This allows for all the valid keys in the key ring 
                                         to be exported. Once set, this cannot be disabled. Defaults to False.
            allow_plaintext_backup (bool, optional): If set, enables taking backup of named key in the plaintext format. 
                                                     Once set, this cannot be disabled. Defaults to False.
            auto_rotate_period (str, optional): The period at which this key should be rotated automatically. Setting this 
                                                to "0" will disable automatic key rotation. This value cannot be shorter 
                                                than one hour. When no value is provided, the period remains unchanged. 
                                                Defaults to "".

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            cur_info = self.read_key(mount_path, name)
            if cur_info is None:
                return False
            
            payload = dict()
            has_change = False
            
            if min_decryption_version != cur_info["min_decryption_version"]:
                payload["min_decryption_version"] = min_decryption_version
                has_change = True

            if min_encryption_version != cur_info["min_encryption_version"]:
                payload["min_encryption_version"] = min_encryption_version
                has_change = True

            if deletion_allowed != cur_info["deletion_allowed"]:
                payload["deletion_allowed"] = deletion_allowed
                has_change = True

            if exportable != cur_info["exportable"]:
                if cur_info["exportable"]:
                    self.logger.error(f"{__class__.__name__} - update key config error: once set exportable=True, "
                                      f"this cannot be disabled")
                    return False
                payload["exportable"] = exportable
                has_change = True

            if allow_plaintext_backup != cur_info["allow_plaintext_backup"]:
                if cur_info["allow_plaintext_backup"]:
                    self.logger.error(f"{__class__.__name__} - update key config error: once set allow_plaintext_backup=True, "
                                      f"this cannot be disabled")
                    return False
                payload["allow_plaintext_backup"] = allow_plaintext_backup
                has_change = True

            if auto_rotate_period != "":
                if rotate_period.value > 0:
                    rotate_period = VaultDuration(auto_rotate_period)
                    lower_period = VaultDuration("1h")
                    if rotate_period < lower_period:
                        self.logger.error(f"{__class__.__name__} - update key config error: The value of auto_rotate_period "
                                          f"cannot be shorter than one hour")
                        return False
                payload["auto_rotate_period"] = auto_rotate_period

            if has_change:
                url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
                token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
                res = requests.post(url+f"{mount_path}/keys/{name}/config", headers={"X-Vault-Token": token}, data=json.dumps(payload))
                if res.status_code == 200 or res.status_code == 204:
                    return True
                else:
                    self._log_error_response(__class__.__name__, res, "update key config error")
                    return False
            else:
                self.logger.warning(f"{__class__.__name__} - update key config warning: no changes")
                return True

        return False

    def rotate_key(self, mount_path: str, name: str):
        """rotate the version of the named key

        After rotation, new plaintext requests will be encrypted with the new version of the key. 
        To upgrade ciphertext to be encrypted with the latest version of the key, use the rewrap 
        endpoint. This is only supported with keys that support encryption and decryption operations.

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#rotate-key for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the key to rotate

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - rotate key error: key '{name}' not found")
                return False
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/keys/{name}/rotate", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "rotate key error")
                return False

        return False

    # TODO: wait for testing
    def sign_csr(self, 
                 mount_path: str,
                 name: str,
                 version: str = "",
                 csr: str = ""):
        """signs a CSR with the named key

        Allowing the key material never to leave Transit. If no template CSR is specified, 
        an empty CSR is signed, otherwise, a copy of the specified CSR with key material 
        replaced with this key material is signed.

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-csr for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the key to sign the CSR with.
            version (str, optional): Specifies the version of the CSR key to use for signing. 
                                     If the version is set to latest or is not set, the current 
                                     key will be returned. Defaults to "".
            csr (str, optional): Optional PEM-encoded CSR template to use as a basis for the new 
                                 CSR signed by this key. If not set, an empty CSR is used. Defaults to "".

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - sign csr error: key '{name}' not found")
                return False
            
            params = []

            if version != "":
                params.append(f"version={version}")
            
            if csr != "":
                params.append(f"csr={csr}")

            if len(params) > 0:
                params = "?" + "&".join(params)
            else:
                params = ""

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/keys/{name}/csr", headers={"X-Vault-Token": token}, params=params)
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "rotate key error")
                return False
        
        return False

    # TODO: wait for testing
    def set_certificate_chain(self, 
                              mount_path: str,
                              name: str,
                              certificate_chain: str,
                              version: str = ""):
        """set the certificate chain associated with the named key

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#set-certificate-chain for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the key to import the certificate chain against
            certificate_chain (str): A PEM encoded certificate chain. It should be composed by one or more concatenated 
                                     PEM blocks and ordered starting from the end-entity certificate.
            version (str, optional): Specifies the version of the key to import the chain against. If the version is 
                                     set to latest or is not set, the current key will be returned. Defaults to "".

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            url += f"{mount_path}/keys/{name}/set-certificate?certificate_chain={certificate_chain}"
            if version != "":
                url += f"&version={version}"
            res = requests.post(url, headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "set certificate chain error")
                return False

        return False

    # TODO: wait for testing
    def securely_export_key(self, 
                            mount_path: str,
                            destination: str,
                            source: str,
                            version: str = ""):
        """export imported key securely

        This endpoint returns a wrapped copy of the `source` key, protected by the `destination` key using the BYOK method 
        accepted by the `/transit/keys/:name/import` API. This allows an operator using two separate Vault instances to 
        secure established shared key material, without exposing either key in plaintext and needing to run a manual BYOK 
        import using the CLI helper utility.

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#securely-export-key for more details.

        Args:
            mount_path (str)
            destination (str): Specifies the name of the key to encrypt the `source` key to: this is usually another mount 
                               or cluster's wrapping key (from `/transit/wrapping_key`).
            source (str): Specifies the source key to encrypt, to copy (encrypted) to another cluster.
            version (str, optional): Specifies the version of the source key to wrap. If omitted, all versions of the key 
                                     will be returned. This is specified as part of the URL. If the version is set to latest, 
                                     the current key will be returned. Defaults to "".

        Returns:
            dict or None: return the key in dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            url += f"{mount_path}/byok-export/{destination}/{source}"
            if version != "":
                url += f"/{version}"
            res = requests.get(url, headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "securely export key error")
                return None
        
        return None

    # TODO: wait for testing
    def export_key(self, 
                   mount_path: str,
                   key_type: str,
                   name: str,
                   version: str = ""):
        """export the named key

        The keys object shows the value of the key for each version. If version is specified, the specific version will be returned. 
        If latest is provided as the version, the current key will be provided. Depending on the type of key, different information 
        may be returned. The key must be exportable to support this operation and the version must still be valid.

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#export-key for more details.

        Args:
            mount_path (str)
            key_type (str): Specifies the type of the key to export
            name (str): Specifies the name of the key to read information about
            version (str, optional): Specifies the version of the key to read. If omitted, all versions of the key will be returned. 
                                     This is specified as part of the URL. If the version is set to latest, the current key will be 
                                     returned. Defaults to "".

        Returns:
            dict or None: return the key in dict if success, otherwise return None
        """
        if self.is_auth:
            valid_key_type = ["encryption-key", "signing-key", "hmac-key", "public-key", "certificate-chain"]
            if key_type not in valid_key_type:
                self.logger.error(f"{__class__.__name__} - export key error: invalid key_type: {key_type}. Valid values are: {valid_key_type}")
                return None
            
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - export key error: key '{name}' not found")
                return None
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            url += f"{mount_path}/export/{key_type}"
            if version != "":
                url += f"/{version}"
            res = requests.get(url, headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "export key error")
                return None

        return None

    def write_global_keys_config(self, mount_path: str, disable_upsert: bool = False):
        """write global key configuration

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#write-keys-configuration for more details.

        Args:
            mount_path (str)
            disable_upsert (bool, optional): Specifies whether to disable upserting on encryption 
                                             (automatic creation of unknown keys). Defaults to False.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            current_config = self.read_global_keys_config(mount_path)
            if current_config is None:
                return False
            else:
                if current_config["disable_upsert"] == disable_upsert:
                    self.logger.warning(f"{__class__.__name__} - write global keys config warning: no change on disable_upsert")
                    return False
            
            payload = dict(disable_upsert=disable_upsert)

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/config/keys/", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "write global keys config error")
                return False

        return False

    def read_global_keys_config(self, mount_path: str):
        """read global key configuration

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#read-keys-configuration for more details.

        Args:
            mount_path (str)

        Returns:
            dict or None: return global key configuration in dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/config/keys/", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "read global keys config error")
                return None

        return None

    # TODO: wait for testing
    def encrypt_data(self, 
                     mount_path: str,
                     name: str,
                     plaintext: str = "",
                     associated_data: str = "",
                     context: str = "",
                     key_version: Optional[int] = None,
                     nonce: str = "",
                     reference: str = "",
                     batch_input: Optional[List[dict]] = None,
                     partial_failure_response_code: int = 400):
        """encrypt the provided plaintext using the named key

        NOTE: Although the HTTP API of Vault allow to create key when encrypting data, we hope you use `create_key()` to create key. 
              Thus, it will raise a warning when specifying a non-existent key.

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#encrypt-data for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to encrypt against
            plaintext (str, optional): Specifies base64 encoded plaintext to be encoded. Defaults to "".
            associated_data (str, optional): Specifies base64 encoded associated data (also known as additional data or AAD) 
                                             to also be authenticated with AEAD ciphers (`aes128-gcm96`, `aes256-gcm`, and 
                                             `chacha20-poly1305`). Defaults to "".
            context (str, optional): Specifies the base64 encoded context for key derivation. This is required if key derivation 
                                     is enabled for this key. Defaults to "".
            key_version (Optional[int], optional): Specifies the version of the key to use for encryption. If not set, uses the 
                                                   latest version. Must be greater than or equal to the key's `min_encryption_version`, 
                                                   if set. Defaults to None.
            nonce (str, optional): Specifies the base64 encoded nonce value. This must be provided if convergent encryption is 
                                   enabled for this key and the key was generated with Vault 0.6.1. Not required for keys created 
                                   in 0.6.2+. The value must be exactly 96 bits (12 bytes) long and the user must ensure that for 
                                   any given context (and thus, any given encryption key) this nonce value is never reused. Defaults 
                                   to "".
            reference (str, optional): A user-supplied string that will be present in the `reference` field on the corresponding 
                                       `batch_results` item in the response, to assist in understanding which result corresponds 
                                       to a particular input. Only valid on batch requests when using ‘batch_input’ below. Defaults 
                                       to "".
            batch_input (Optional[List[dict]], optional): Specifies a list of items to be encrypted in a single batch. When this 
                                                          parameter is set, if the parameters 'plaintext', 'context' and 'nonce' 
                                                          are also set, they will be ignored. Any batch output will preserve the 
                                                          order of the batch input. Defaults to None.
            partial_failure_response_code (int, optional): Ordinarily, if a batch item fails to encrypt due to a bad input, but other 
                                                           batch items succeed, the HTTP response code is 400 (Bad Request). Some 
                                                           applications may want to treat partial failures differently. Providing the 
                                                           parameter returns the given response code integer instead of a failed status 
                                                           code in this case. If all values fail an error code is still returned. Be 
                                                           warned that some failures (such as failure to decrypt) could be indicative 
                                                           of a security breach and should not be ignored. Defaults to 400.

        Returns:
            dict or None: return the cipher text in dict if success, otherwise return None
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.warning(f"{__class__.__name__} - encrypt data warning: key '{name}' not found. Although the HTTP API of Vault "
                                    f"allow to create key when encrypting data, we hope you use `create_key()` to create key")
                return None

            payload = dict()
            
            if batch_input is None:
                if not is_base64(plaintext):
                    self.logger.error(f"{__class__.__name__} - encrypt data error: the plaintext must be base64 encoded")
                    return None
                payload["plaintext"] = plaintext
            
            if associated_data != "":
                if not is_base64(associated_data):
                    self.logger.error(f"{__class__.__name__} - encrypt data error: the associated_data must be base64 encoded if set")
                    return None
                payload["associated_data"] = associated_data
            
            if batch_input is None and context != "":
                if not is_base64(context):
                    self.logger.error(f"{__class__.__name__} - encrypt data error: the context must be base64 encoded if set")
                    return None
                payload["context"] = context

            if key_version is not None:
                if not is_int(key_version):
                    self.logger.error(f"{__class__.__name__} - encrypt data error: the key_version must be an integer")
                    return None
                if key_version < self.read_key(mount_path, name)["min_encryption_version"]:
                    self.logger.error(f"{__class__.__name__} - encrypt data error: greater than or equal to the key's "
                                      f"`min_encryption_version`, if set")
                    return None
                payload["key_version"] = key_version

            if batch_input is None and nonce != "":
                if not is_base64(nonce):
                    self.logger.error(f"{__class__.__name__} - encrypt data error: the nonce must be base64 encoded if set")
                    return None
                if len(nonce) != 12:
                    self.logger.error(f"{__class__.__name__} - encrypt data error: the nonce must be exactly 96 bits (12 bytes) long if set")
                    return None
                payload["nonce"] = nonce
            
            if batch_input is not None:
                if reference != "":
                    payload["reference"] = reference
                payload["batch_input"] = batch_input

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/encrypt/{name}", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            elif res.status_code == partial_failure_response_code:
                self.logger.error(f"{__class__.__name__} - encrypt data error: partial failure raised")
                return None
            else:
                self._log_error_response(__class__.__name__, res, "encrypt data error")
                return None

        return None

    # TODO: wait for testing
    def decrypt_data(self, 
                     mount_path: str,
                     name: str,
                     ciphertext: str = "",
                     associated_data: str = "",
                     context: str = "",
                     nonce: str = "",
                     reference: str = "",
                     batch_input: Optional[List[dict]] = None,
                     partial_failure_response_code: int = 400):
        """decrypt the provided ciphertext using the named key

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#decrypt-data for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to decrypt against.
            ciphertext (str, optional): Specifies the ciphertext to decrypt. Defaults to "".
            associated_data (str, optional): Specifies base64 encoded associated data (also known as additional data or AAD) 
                                             to also be authenticated with AEAD ciphers (`aes128-gcm96`, `aes256-gcm`, and 
                                             `chacha20-poly1305`). Defaults to "".
            context (str, optional): Specifies the base64 encoded context for key derivation. This is required if key derivation 
                                     is enabled for this key. Defaults to "".
            nonce (str, optional): Specifies a base64 encoded nonce value used during encryption. Must be provided if convergent 
                                   encryption is enabled for this key and the key was generated with Vault 0.6.1. Not required 
                                   for keys created in 0.6.2+. Defaults to "".
            reference (str, optional): A user-supplied string that will be present in the `reference` field on the corresponding 
                                       `batch_results` item in the response, to assist in understanding which result corresponds 
                                       to a particular input. Only valid on batch requests when using ‘batch_input’ below. 
                                       Defaults to "".
            batch_input (Optional[List[dict]], optional): Specifies a list of items to be decrypted in a single batch. When 
                                                          this parameter is set, if the parameters 'ciphertext', 'context' and 
                                                          'nonce' are also set, they will be ignored. Any batch output will 
                                                          preserve the order of the batch input. Defaults to None.
            partial_failure_response_code (int, optional): Ordinarily, if a batch item fails to encrypt due to a bad input, but 
                                                           other batch items succeed, the HTTP response code is 400 (Bad Request). 
                                                           Some applications may want to treat partial failures differently. 
                                                           Providing the parameter returns the given response code integer instead 
                                                           of a failed status code in this case. If all values fail an error code is 
                                                           still returned. Be warned that some failures (such as failure to decrypt) 
                                                           could be indicative of a security breach and should not be ignored. 
                                                           Defaults to 400.

        Returns:
            dict or None: return the plain text in dict if success, otherwise return None
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - decrypt data error: key '{name}' not found")
                return None
            
            payload = dict()

            if batch_input is None:
                if not is_base64(ciphertext):
                    self.logger.error(f"{__class__.__name__} - decrypt data error: the ciphertext must be base64 encoded")
                    return None
                payload["ciphertext"] = ciphertext

            if associated_data != "":
                if not is_base64(associated_data):
                    self.logger.error(f"{__class__.__name__} - decrypt data error: the associated_data must be base64 encoded if set")
                    return None
                payload["associated_data"] = associated_data

            if batch_input is None and context != "":
                if not is_base64(context):
                    self.logger.error(f"{__class__.__name__} - decrypt data error: the context must be base64 encoded if set")
                    return None
                payload["context"] = context

            if batch_input is None and nonce != "":
                if not is_base64(nonce):
                    self.logger.error(f"{__class__.__name__} - decrypt data error: the nonce must be base64 encoded if set")
                    return None
                payload["nonce"] = nonce

            if batch_input is not None:
                if reference != "":
                    payload["reference"] = reference
                payload["batch_input"] = batch_input

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/decrypt/{name}", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            elif res.status_code == partial_failure_response_code:
                self.logger.error(f"{__class__.__name__} - decrypt data error: partial failure raised")
                return None
            else:
                self._log_error_response(__class__.__name__, res, "decrypt data error")
                return None
        
        return None

    # TODO: wait for testing
    def rewrap_data(self, 
                    mount_path: str,
                    name: str,
                    ciphertext: str = "",
                    context: str = "",
                    key_version: Optional[int] = None,
                    nonce: str = "",
                    reference: str = "",
                    batch_input: Optional[List[dict]] = None):
        """rewrap the provided ciphertext using the latest version of the named key

        Because this never returns plaintext, it is possible to delegate this functionality to untrusted users or scripts

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#rewrap-data for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to re-encrypt against
            ciphertext (str, optional): Specifies the ciphertext to re-encrypt. Defaults to "".
            context (str, optional): Specifies the base64 encoded context for key derivation. This is required if key 
                                     derivation is enabled. Defaults to "".
            key_version (Optional[int], optional): Specifies the version of the key to use for the operation. If not 
                                                   set, uses the latest version. Must be greater than or equal to the 
                                                   key's `min_encryption_version`, if set. Defaults to None.
            nonce (str, optional): Specifies a base64 encoded nonce value used during encryption. Must be provided if 
                                   convergent encryption is enabled for this key and the key was generated with Vault 
                                   0.6.1. Not required for keys created in 0.6.2+. Defaults to "".
            reference (str, optional): A user-supplied string that will be present in the `reference` field on the 
                                       corresponding `batch_results` item in the response, to assist in understanding 
                                       which result corresponds to a particular input. Only valid on batch requests when 
                                       using ‘batch_input’ below. Defaults to "".
            batch_input (Optional[List[dict]], optional): Specifies a list of items to be re-encrypted in a single batch. 
                                                          When this parameter is set, if the parameters 'ciphertext', 
                                                          'context' and 'nonce' are also set, they will be ignored. Any 
                                                          batch output will preserve the order of the batch input. 
                                                          Defaults to None.

        Returns:
            dict or None: return the re-encrypted cipher text in dict if success, otherwise return None
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - rewrap data error: key '{name}' not found")
                return None
            
            payload = dict()
            
            if batch_input is None:
                if not is_base64(ciphertext):
                    self.logger.error(f"{__class__.__name__} - rewrap data error: the ciphertext must be base64 encoded")
                    return None
                payload["ciphertext"] = ciphertext
                
            if key_version is not None:
                if not is_int(key_version):
                    self.logger.error(f"{__class__.__name__} - rewrap data error: the key_version must be an integer")
                    return None
                if key_version < self.read_key(mount_path, name)["min_encryption_version"]:
                    self.logger.error(f"{__class__.__name__} - rewrap data error: greater than or equal to the key's "
                                      f"`min_encryption_version`, if set")
                    return None
                payload["key_version"] = key_version

            if batch_input is None and context != "":
                if not is_base64(context):
                    self.logger.error(f"{__class__.__name__} - rewrap data error: the context must be base64 encoded if set")
                    return None
                payload["context"] = context

            if batch_input is None and nonce != "":
                if not is_base64(nonce):
                    self.logger.error(f"{__class__.__name__} - rewrap data error: the nonce must be base64 encoded if set")
                    return None
                payload["nonce"] = nonce

            if batch_input is not None:
                if reference != "":
                    payload["reference"] = reference
                payload["batch_input"] = batch_input

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/rewrap/{name}", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "rewrap data error")
                return None
        
        return None

    # TODO: wait for testing
    def generate_data_key(self, 
                          mount_path: str,
                          type_name: str,
                          name: str,
                          context: str = "",
                          nonce: str = "",
                          bits: int = 256):
        """generate a new high-entropy key and the value encrypted with the named key
        
        Optionally return the plaintext of the key as well. Whether plaintext is returned depends on the path; 
        as a result, you can use Vault ACL policies to control whether a user is allowed to retrieve the 
        plaintext value of a key. This is useful if you want an untrusted user or operation to generate keys 
        that are then made available to trusted users.
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#generate-data-key for more details.

        Args:
            mount_path (str)
            type_name (str): Specifies the type of key to generate. If `plaintext`, the plaintext key will be 
                             returned along with the ciphertext. If `wrapped`, only the ciphertext value will 
                             be returned.
            name (str): Specifies the name of the encryption key to use to encrypt the datakey.
            context (str, optional): Specifies the key derivation context, provided as a base64-encoded string. 
                                     This must be provided if derivation is enabled. Defaults to "".
            nonce (str, optional): Specifies a nonce value, provided as base64 encoded. Must be provided if 
                                   convergent encryption is enabled for this key and the key was generated with 
                                   Vault 0.6.1. Not required for keys created in 0.6.2+. The value must be exactly 
                                   96 bits (12 bytes) long and the user must ensure that for any given context 
                                   (and thus, any given encryption key) this nonce value is never reused. Defaults 
                                   to "".
            bits (int, optional): Specifies the number of bits in the desired key. Can be 128, 256, or 512. Defaults 
                                  to 256.

        Returns:
            dict or None: return the data key in dict if success, otherwise return None
        """
        if self.is_auth:
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - generate data key error: key '{name}' not found")
                return None
            
            if type_name not in ["plaintext", "wrapped"]:
                self.logger.error(f"{__class__.__name__} - generate data key error: type_name must be one of: "
                                  f"plaintext, wrapped")
                return None
            
            payload = dict()
            
            if context != "":
                if not is_base64(context):
                    self.logger.error(f"{__class__.__name__} - generate data key error: the context must be "
                                      f"base64 encoded if set")
                    return None
                payload["context"] = context
                
            if nonce != "":
                if not is_base64(nonce):
                    self.logger.error(f"{__class__.__name__} - generate data key error: the nonce must be "
                                      f"base64 encoded if set")
                    return None
                if len(nonce) != 12:
                    self.logger.error(f"{__class__.__name__} - generate data key error: the nonce must be "
                                      f"exactly 96 bits (12 bytes) long if set")
                    return None
                payload["nonce"] = nonce
            
            if bits not in [128, 256, 512]:
                self.logger.error(f"{__class__.__name__} - generate data key error: bits should be one of: "
                                  f"128, 256, 512")
                return None
            payload["bits"] = bits
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/datakey/{type_name}/{name}", 
                                headers={"X-Vault-Token": token}, 
                                data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "generate data key error")
                return None
            
        return None

    # TODO: wait for testing
    def generate_random_bytes(self, 
                              mount_path: str,
                              bytes_num: int = 32,
                              out_format: str = "base64",
                              source: str = "platform"):
        """return high-quality random bytes of the specified length
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#generate-random-bytes for more details.

        Args:
            mount_path (str)
            bytes_num (int, optional): Specifies the number of bytes to return. This value can be specified 
                                       either in the request body, or as a part of the URL. Defaults to 32.
            out_format (str, optional): Specifies the output encoding. Valid options are `hex` or `base64`. 
                                        Defaults to "base64".
            source (str, optional): Specifies the source of the requested bytes. `platform`, the default, 
                                    sources bytes from the platform's entropy source. `seal` sources from 
                                    entropy augmentation (enterprise only). `all` mixes bytes from all 
                                    available sources. Defaults to "platform".

        Returns:
            dict or None: return the random bytes in dict if success, otherwise return None
        """
        if self.is_auth:
            payload = dict()
            
            if out_format not in ["hex", "base64"]:
                self.logger.error(f"{__class__.__name__} - generate random bytes error: out_format should be one of: "
                                  f"hex, base64")
                return None
            payload["format"] = out_format
            
            if source not in ["platform", "seal", "all"]:
                self.logger.error(f"{__class__.__name__} - generate random bytes error: source should be one of: "
                                  f"platform, seal, all")
                return None
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            url += f"{mount_path}/random"
            if source in ["seal", "all"]:
                url += f"/{source}"
            url += f"/{bytes_num}"
            res = requests.post(url, headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "generate random bytes error")
                return None
            
        return None

    # TODO: wait for testing
    def hash_data(self, 
                  mount_path: str,
                  input_data: str,
                  algorithm: str = "sha2-256",
                  out_format: str = "hex"):
        """return the cryptographic hash of given data using the specified algorithm
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#hash-data for more details.

        Args:
            mount_path (str)
            input_data (str): Specifies the base64 encoded input data.
            algorithm (str, optional): Specifies the hash algorithm to use. This can also be specified as 
                                       part of the URL. Currently-supported algorithms are: sha2-224, 
                                       sha2-256, sha2-384, sha2-512, sha3-224, sha3-256, sha3-384, sha3-512. 
                                       Defaults to "sha2-256".
            out_format (str, optional): Specifies the output encoding. This can be either `hex` or `base64`. 
                                        Defaults to "hex".

        Returns:
            dict or None: return the hash data in dict if success, otherwsie return None
        """
        if self.is_auth:
            support_algorithm = ["sha2-224", "sha2-256", "sha2-384", "sha2-512", 
                                 "sha3-224", "sha3-256", "sha3-384", "sha3-512"]
            if algorithm not in support_algorithm:
                self.logger.error(f"{__class__.__name__} - hash data error: algorithm must be one of: "
                                  f"{', '.join(support_algorithm)}")
                return None
            
            payload = dict()
            
            if not is_base64(input_data):
                self.logger.error(f"{__class__.__name__} - hash data error: the input_data must be base64 encoded")
                return None
            payload["input"] = input_data
            
            if out_format not in ["hex", "base64"]:
                self.logger.error(f"{__class__.__name__} - hash data error: out_format should be one of: hex, base64")
                return None
            payload["format"] = out_format
            
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/hash/{algorithm}", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "hash data error")
                return None
            
        return None

    # TODO: wait for testing
    def generate_hmac(self, 
                      mount_path: str,
                      name: str,
                      key_version: Optional[int] = None,
                      algorithm: str = "sha2-256",
                      input_data: str = "",
                      reference: str = "",
                      batch_input: Optional[List[dict]] = None):
        """return the digest of given data using the specified hash algorithm and the named key
        
        The key can be of any type supported by transit, as each transit key version has an independent, 
        random 256-bit HMAC secret key. If the key is of a type that supports rotation, the latest (current) 
        version will be used.
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#generate-hmac for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to generate hmac against.
            key_version (Optional[int], optional): Specifies the version of the key to use for the operation. 
                                                   If not set, uses the latest version. Must be greater than 
                                                   or equal to the key's `min_encryption_version`, if set. 
                                                   Defaults to None.
            algorithm (str, optional): Specifies the hash algorithm to use. This can also be specified as part 
                                       of the URL. Currently-supported algorithms are: sha2-224, sha2-256, 
                                       sha2-384, sha2-512, sha3-224, sha3-256, sha3-384, sha3-512. Defaults to 
                                       "sha2-256".
            input_data (str, optional): Specifies the base64 encoded input data. One of `input` or `batch_input` 
                                        must be supplied. Defaults to "".
            reference (str, optional): A user-supplied string that will be present in the `reference` field on 
                                       the corresponding `batch_results` item in the response, to assist in 
                                       understanding which result corresponds to a particular input. Only valid 
                                       on batch requests when using ‘batch_input’ below. Defaults to "".
            batch_input (Optional[List[dict]], optional): Specifies a list of items for processing. When this 
                                                          parameter is set, if the parameter 'input' is also set, 
                                                          it will be ignored. Responses are returned in the 
                                                          'batch_results' array component of the 'data' element 
                                                          of the response. Any batch output will preserve the 
                                                          order of the batch input. If the input data value of 
                                                          an item is invalid, the corresponding item in the 
                                                          'batch_results' will have the key 'error' with a value 
                                                          describing the error. Defaults to None.

        Returns:
            dict or None: return the digest of given data in dict if success, otherwise return None
        """
        if self.is_auth:
            if input_data == "" and batch_input is None:
                self.logger.error(f"{__class__.__name__} - generate hmac error: One of `input` or `batch_input` "
                                  f"must be supplied")
                return None
            
            support_algorithm = ["sha2-224", "sha2-256", "sha2-384", "sha2-512", 
                                 "sha3-224", "sha3-256", "sha3-384", "sha3-512"]
            if algorithm not in support_algorithm:
                self.logger.error(f"{__class__.__name__} - generate hmac error: algorithm must be one of: "
                                  f"{', '.join(support_algorithm)}")
                return None
            
            payload = dict()
            
            if batch_input is None:
                if not is_base64(input_data):
                    self.logger.error(f"{__class__.__name__} - generate hmac error: the input_data must be base64 encoded")
                    return None
                payload["input"] = input_data
                
            if key_version is not None:
                if not is_int(key_version):
                    self.logger.error(f"{__class__.__name__} - generate hmac error: the key_version must be an integer")
                    return None
                if key_version < self.read_key(mount_path, name)["min_encryption_version"]:
                    self.logger.error(f"{__class__.__name__} - generate hmac error: greater than or equal to the key's "
                                      f"`min_encryption_version`, if set")
                    return None
                payload["key_version"] = key_version
                
            if batch_input is not None:
                if reference != "":
                    payload["reference"] = reference
                payload["batch_input"] = batch_input
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/hmac/{name}/{algorithm}", 
                                headers={"X-Vault-Token": token}, 
                                data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "generate hmac error")
                return None
                        
        return None

    # TODO: wait for testing
    def sign_data(self, 
                  mount_path: str,
                  name: str,
                  key_version: Optional[int] = None,
                  hash_algorithm: str = "sha2-256",
                  input_data: str = "",
                  reference: str = "",
                  batch_input: Optional[List[dict]] = None,
                  context: str = "",
                  prehashed: bool = False,
                  signature_algorithm: str = "",
                  marshaling_algorithm: str = "",
                  salt_length: str = ""):
        """return the cryptographic signature of the given data using the named key and the specified hash algorithm
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key to use for signing.
            key_version (Optional[int], optional): Specifies the version of the key to use for signing. 
                                                   If not set, uses the latest version. Must be greater 
                                                   than or equal to the key's `min_encryption_version`, 
                                                   if set. Defaults to None.
            hash_algorithm (str, optional): Specifies the hash algorithm to use for supporting key types 
                                            (notably, not including `ed25519` which specifies its own hash 
                                            algorithm). This can also be specified as part of the URL. 
                                            Currently-supported algorithms are: sha1, sha2-224, sha2-256, 
                                            sha2-384, sha2-512, sha3-224, sha3-384, sha3-512, none. Defaults 
                                            to "sha2-256".
            input_data (str, optional): Specifies the base64 encoded input data. One of `input` or `batch_input` 
                                        must be supplied. Defaults to "".
            reference (str, optional): A user-supplied string that will be present in the `reference` field 
                                       on the corresponding `batch_results` item in the response, to assist 
                                       in understanding which result corresponds to a particular input. Only 
                                       valid on batch requests when using ‘batch_input’ below.. Defaults to "".
            batch_input (Optional[List[dict]], optional): Specifies a list of items for processing. When this 
                                                          parameter is set, any supplied 'input' or 'context' 
                                                          parameters will be ignored. Responses are returned 
                                                          in the 'batch_results' array component of the 'data' 
                                                          element of the response. Any batch output will preserve 
                                                          the order of the batch input. If the input data value 
                                                          of an item is invalid, the corresponding item in the 
                                                          'batch_results' will have the key 'error' with a value 
                                                          describing the error. Defaults to None.
            context (str, optional): Base64 encoded context for key derivation. Required if key derivation is 
                                     enabled; currently only available with ed25519 keys. Defaults to "".
            prehashed (bool, optional): Set to `true` when the input is already hashed. If the key type is 
                                        `rsa-2048`, `rsa-3072` or `rsa-4096`, then the algorithm used to hash 
                                        the input should be indicated by the `hash_algorithm` parameter. Just 
                                        as the value to sign should be the base64-encoded representation of 
                                        the exact binary data you want signed, when set, `input` is expected 
                                        to be base64-encoded binary hashed data, not hex-formatted. (As an 
                                        example, on the command line, you could generate a suitable input via 
                                        `openssl dgst -sha256 -binary | base64`.). Defaults to False.
            signature_algorithm (str, optional): When using a RSA key, specifies the RSA signature algorithm 
                                                 to use for signing. Supported signature types are: pss, pkcs1v15. 
                                                 Defaults to "".
            marshaling_algorithm (str, optional): Specifies the way in which the signature should be marshaled. 
                                                  This currently only applies to ECDSA keys. Supported types are: 
                                                  asn1, jws. Defaults to "".
            salt_length (str, optional): The salt length used to sign. This currently only applies to the RSA PSS 
                                         signature scheme. Options are: auto, hash, or an integer between the 
                                         minimum and the maximum permissible salt lengths for the given RSA key size. 
                                         Defaults to "".

        Returns:
            dict or None: return the signature in dict if success, otherwise return None
        """
        if self.is_auth:
            if input_data == "" and batch_input is None:
                self.logger.error(f"{__class__.__name__} - sign data error: One of `input` or `batch_input` "
                                  f"must be supplied")
                return None
            
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - sign data error: key '{name}' not found")
                return None
            
            payload = dict()
            
            support_hash_algorithm = ["sha1", "sha2-224", "sha2-256", "sha2-384", "sha2-512", 
                                      "sha3-224", "sha3-384", "sha3-512", "none"]
            if hash_algorithm not in support_hash_algorithm:
                self.logger.error(f"{__class__.__name__} - sign data error: hash_algorithm must be one of: "
                                  f"{', '.join(support_hash_algorithm)}")
                return None
            
            if key_version is not None:
                if not is_int(key_version):
                    self.logger.error(f"{__class__.__name__} - sign data error: the key_version must be an integer")
                    return None
                if key_version < self.read_key(mount_path, name)["min_encryption_version"]:
                    self.logger.error(f"{__class__.__name__} - sign data error: greater than or equal to the key's "
                                      f"`min_encryption_version`, if set")
                    return None
                payload["key_version"] = key_version
                
            if batch_input is None:
                if not is_base64(input_data):
                    self.logger.error(f"{__class__.__name__} - sign data error: the input_data must be base64 encoded")
                    return None
                payload["input"] = input_data
                
            if batch_input is None and context != "":
                if not is_base64(context):
                    self.logger.error(f"{__class__.__name__} - sign data error: the context must be base64 encoded if set")
                    return None
                payload["context"] = context
                
            if batch_input is not None:
                if reference != "":
                    payload["reference"] = reference
                payload["batch_input"] = batch_input
                
            if prehashed:
                payload["prehashed"] = prehashed
            
            if signature_algorithm != "":
                if signature_algorithm not in ["pss", "pkcs1v15"]:
                    self.logger.error(f"{__class__.__name__} - sign data error: signature_algorithm must be one of: pss, pkcs1v15")
                    return None
                payload["signature_algorithm"] = signature_algorithm
                
            if marshaling_algorithm != "":
                if marshaling_algorithm not in ["asn1", "jws"]:
                    self.logger.error(f"{__class__.__name__} - sign data error: marshaling_algorithm must be one of: psasn1s, jws")
                    return None
                payload["marshaling_algorithm"] = marshaling_algorithm
                
            if salt_length != "":
                payload["salt_length"] = salt_length
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/sign/{name}/{hash_algorithm}", 
                                headers={"X-Vault-Token": token}, 
                                data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "sign data error")
                return None
        
        return None

    # TODO: wait for testing
    def verify_signed_data(self, 
                           mount_path: str,
                           name: str,
                           hash_algorithm: str = "sha2-256",
                           input_data: str = "",
                           signature: str = "",
                           hmac: str = "",
                           reference: str = "",
                           batch_input: Optional[List[dict]] = None,
                           context: str = "",
                           prehashed: bool = False,
                           signature_algorithm: str = "",
                           marshaling_algorithm: str = "",
                           salt_length: str = ""):
        """verify whether the provided signature is valid for the given data
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#verify-signed-data for more details.

        Args:
            mount_path (str)
            name (str): Specifies the name of the encryption key that was used to generate the signature or HMAC.
            hash_algorithm (str, optional): Specifies the hash algorithm to use. This can also be specified as 
                                            part of the URL. Currently-supported algorithms are: sha1, sha2-224, 
                                            sha2-256, sha2-384, sha2-512, sha3-224, sha3-384, sha3-512, none. 
                                            Defaults to "sha2-256".
            input_data (str, optional): Specifies the base64 encoded input data. One of `input` or `batch_input` 
                                        must be supplied. Defaults to "".
            signature (str, optional): Specifies the signature output from the `/transit/sign` function. Either 
                                       this must be supplied or `hmac` must be supplied. Defaults to "".
            hmac (str, optional): Specifies the signature output from the `/transit/hmac` function. Either this 
                                  must be supplied or `signature` must be supplied. Defaults to "".
            reference (str, optional): A user-supplied string that will be present in the `reference` field on 
                                       the corresponding `batch_results` item in the response, to assist in 
                                       understanding which result corresponds to a particular input. Only valid 
                                       on batch requests when using ‘batch_input’ below. Defaults to "".
            batch_input (Optional[List[dict]], optional): Specifies a list of items for processing. When this 
                                                          parameter is set, any supplied 'input', 'hmac' or 
                                                          'signature' parameters will be ignored. 'batch_input' 
                                                          items should contain an 'input' parameter and either 
                                                          an 'hmac' or 'signature' parameter. All items in the 
                                                          batch must consistently supply either 'hmac' or 
                                                          'signature' parameters. It is an error for some items 
                                                          to supply 'hmac' while others supply 'signature'. 
                                                          Responses are returned in the 'batch_results' array 
                                                          component of the 'data' element of the response. Any 
                                                          batch output will preserve the order of the batch input. 
                                                          If the input data value of an item is invalid, the 
                                                          corresponding item in the 'batch_results' will have 
                                                          the key 'error' with a value describing the error. 
                                                          Defaults to None.
            context (str, optional): Base64 encoded context for key derivation. Required if key derivation is 
                                     enabled; currently only available with ed25519 keys. Defaults to "".
            prehashed (bool, optional): Set to `true` when the input is already hashed. If the key type is 
                                        `rsa-2048`, `rsa-3072` or `rsa-4096`, then the algorithm used to hash 
                                        the input should be indicated by the `hash_algorithm` parameter. Defaults 
                                        to False.
            signature_algorithm (str, optional): When using a RSA key, specifies the RSA signature algorithm to 
                                                 use for signature verification. Supported signature types are: 
                                                 pss pkcs1v15. Defaults to "".
            marshaling_algorithm (str, optional):  Specifies the way in which the signature was originally marshaled. 
                                                   This currently only applies to ECDSA keys. Supported types are: 
                                                   asn1, jws. Defaults to "".
            salt_length (str, optional): The salt length used to sign. This currently only applies to the RSA 
                                         PSS signature scheme. Options are: auto, hash, or an integer between the 
                                         minimum and the maximum permissible salt lengths for the given RSA key size. 
                                         Defaults to "".

        Returns:
            dict or None: return the verification 
        """
        if self.is_auth:
            if input_data == "" and batch_input is None:
                self.logger.error(f"{__class__.__name__} - verify signed data error: One of `input` or `batch_input` "
                                  f"must be supplied")
                return None
            
            if signature != "" and hmac != "":
                self.logger.error(f"{__class__.__name__} - verify signed data data error: cannot specify both signature and hmac")
                return None
            
            exist_keys = self.list_key(mount_path)
            if name not in exist_keys:
                self.logger.error(f"{__class__.__name__} - verify signed data error: key '{name}' not found")
                return None
            
            payload = dict()
            
            support_hash_algorithm = ["sha1", "sha2-224", "sha2-256", "sha2-384", "sha2-512", 
                                      "sha3-224", "sha3-384", "sha3-512", "none"]
            if hash_algorithm not in support_hash_algorithm:
                self.logger.error(f"{__class__.__name__} - verify signed data error: hash_algorithm must be one of: "
                                  f"{', '.join(support_hash_algorithm)}")
                return None
            
            if batch_input is None:
                if not is_base64(input_data):
                    self.logger.error(f"{__class__.__name__} - verify signed data error: the input_data must be base64 encoded")
                    return None
                payload["input"] = input_data
                if signature != "":
                    payload["signature"] = signature
                if hmac != "":
                    payload["hmac"] = hmac
                if context != "":
                    if not is_base64(context):
                        self.logger.error(f"{__class__.__name__} - verify signed data error: the context must be base64 encoded if set")
                        return None
                    payload["context"] = context
                
            if batch_input is not None:
                if reference != "":
                    payload["reference"] = reference
                payload["batch_input"] = batch_input
                
            if prehashed:
                payload["prehashed"] = prehashed
            
            if signature_algorithm != "":
                if signature_algorithm not in ["pss", "pkcs1v15"]:
                    self.logger.error(f"{__class__.__name__} - verify signed data error: signature_algorithm must be one of: "
                                      f"pss, pkcs1v15")
                    return None
                payload["signature_algorithm"] = signature_algorithm
                
            if marshaling_algorithm != "":
                if marshaling_algorithm not in ["asn1", "jws"]:
                    self.logger.error(f"{__class__.__name__} - verify signed data error: marshaling_algorithm must be one of: "
                                      f"psasn1s, jws")
                    return None
                payload["marshaling_algorithm"] = marshaling_algorithm
                
            if salt_length != "":
                payload["salt_length"] = salt_length
                
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/verify/{name}/{hash_algorithm}", 
                                headers={"X-Vault-Token": token}, 
                                data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "verify signed data error")
                return None
            
        return None

    # TODO: wait for testing
    def backup_key(self, mount_path: str, name: str):
        """return a plaintext backup of a named key
        
        The backup contains all the configuration data and keys of all the versions along with the HMAC key. 
        The response from this endpoint can be used with the `/restore` endpoint to restore the key.
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#backup-key for more details.

        Args:
            mount_path (str)
            name (str): Name of the key

        Returns:
            dict or None: return the backup in dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/backup/{name}", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "backup key error")
                return None
            
        return None

    # TODO: wait for testing
    def restore_key(self, 
                    mount_path: str, 
                    backup: str, 
                    name: str = "", 
                    force: bool = False):
        """restore the backup as a named key
        
        This will restore the key configurations and all the versions of the named key along with HMAC keys. 
        The input to this endpoint should be the output of `/backup` endpoint.
        
        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#restore-key for more details.

        Args:
            mount_path (str)
            backup (str): Backed up key data to be restored. This should be the output from the `/backup` endpoint.
            name (str, optional): If set, this will be the name of the restored key. Defaults to "".
            force (bool, optional): If set, force the restore to proceed even if a key by this name already exists. 
                                    Defaults to False.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            payload = dict(backup=backup)
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            url += f"{mount_path}/restore"

            if name != "":
                exist_keys = self.list_key(mount_path)
                if name in exist_keys and not force:
                    self.logger.error(f"{__class__.__name__} - restore key error: key '{name}' not is already existed, "
                                      f"please set force=True and try again")
                    return False
                url += f"/{name}"
            
            if not force:
                payload["force"] = force

            res = requests.post(url, headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "restore key error")
                return False
            
        return False

    # TODO: wait for testing
    def trim_key(self, mount_path: str, name: str, min_available_version: int):
        """trim older key versions setting a minimum version for the keyring

        Once trimmed, previous versions of the key cannot be recovered.

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#trim-key for more details.

        Args:
            mount_path (str)
            name (str): Name of the key
            min_available_version (int): The minimum available version for the key ring. All versions 
                                         before this version will be permanently deleted. This value can 
                                         at most be equal to the lesser of `min_decryption_version` and 
                                         `min_encryption_version`. This is not allowed to be set when either 
                                         `min_encryption_version` or `min_decryption_version` is set to zero.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            key_info = self.read_key(mount_path, name)
            if key_info is None:
                return False
            
            if key_info["min_decryption_version"] == 0 or key_info["min_encryption_version"] == 0:
                self.logger.error(f"{__class__.__name__} - trim key error: do not allow to trim key when "
                                  f"`min_encryption_version` or `min_decryption_version` is set to zero")
                return False
            
            if min_available_version > key_info["min_decryption_version"] or \
                min_available_version > key_info["min_encryption_version"]:
                self.logger.error(f"{__class__.__name__} - trim key error: the min_available_version can at most "
                                  f"be equal to the lesser of `min_decryption_version` and `min_encryption_version`")
                return False

            payload = dict(min_available_version=min_available_version)

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/keys/{name}/trim", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "trim key error")
                return False
        
        return False

    # TODO: wait for testing
    def configure_cache(self, mount_path: str, size: int = 0):
        """configure the transit engine's cache

        Refer to https://developer.hashicorp.com/vault/api-docs/secret/transit#configure-cache for more details.

        Args:
            mount_path (str): _description_
            size (int, optional): Specifies the size in terms of number of entries. A size of `0` means unlimited. 
                                  A Least Recently Used (LRU) caching strategy is used for a non-zero cache size. 
                                  Must be 0 (default) or a value greater or equal to 10 (minimum cache size). 
                                  Defaults to 0.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.is_auth:
            if size != 0 and size < 10:
                self.logger.error(f"{__class__.__name__} - configure cache error: the size must be 0 (default) or "
                                  f"a value greater or equal to 10 (minimum cache size)")
                return False

            payload = dict(size=size)

            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.post(url+f"{mount_path}/cache-config", headers={"X-Vault-Token": token}, data=json.dumps(payload))
            if res.status_code == 200 or res.status_code == 204:
                return True
            else:
                self._log_error_response(__class__.__name__, res, "configure cache error")
                return False

        return False

    def read_transit_cache_config(self, mount_path: str):
        """read the cache config of "mount_path/"

        Args:
            mount_path (str)

        Returns:
            dict or None: return the cache config in dict if success, otherwise return None
        """
        if self.is_auth:
            url = aes_decrypt_text(self.url, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            token = aes_decrypt_text(self.token, key=random_hex(self._key_len, self._seed*2), iv=random_hex(16, self._seed*3))
            res = requests.get(url+f"{mount_path}/cache-config", headers={"X-Vault-Token": token})
            if res.status_code == 200 or res.status_code == 204:
                return res.json()["data"]
            else:
                self._log_error_response(__class__.__name__, res, "read transit cache config error")
                return None
            
        return None

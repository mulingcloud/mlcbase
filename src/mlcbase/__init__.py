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

from .version import Version
from .conifg import ConfigDict, is_config_dict
from .logger import Logger
from .timer import wrap_module_timer, delete_register_modules, runtime_analysis
from .file import mkdir, listdir, get_file_size, get_dir_size, get_meta_info
from .loading import load_json, save_json, load_yaml, save_yaml, load_xml, save_xml
from .encrypt_password import encrypt_password, verify_password
from .entrypt_aes import aes_encrypt_text, aes_decrypt_text, aes_entrypt_file, aes_decrypt_file
from .entrypt_rsa import (create_rsa_keys, rsa_encrypt_text, rsa_decrypt_text, rsa_sign_text,
                          rsa_verify_signature, rsa_encrypt_file, rsa_decrypt_file)
from .vault import VaultAPI
from .database import MySQLAPI
from .remote_connect import SSH, SFTP
from .email import SMTPAPI
from .misc import (is_type, is_bytes, is_str, is_int, is_float, is_bool, is_list, is_dict,
                   is_tuple, is_path, is_net_ok, random_hex)

__all__ = [
    "Version", "ConfigDict", "is_config_dict", "Logger", "wrap_module_timer", "delete_register_modules", 
    "runtime_analysis", "mkdir", "listdir", "get_file_size", "get_dir_size", "get_meta_info", "load_json", 
    "save_json", "load_yaml", "save_yaml", "load_xml", "save_xml", "encrypt_password", "verify_password", 
    "aes_encrypt_text", "aes_decrypt_text", "aes_entrypt_file", "aes_decrypt_file", "create_rsa_keys", 
    "rsa_encrypt_text", "rsa_decrypt_text", "rsa_sign_text", "rsa_verify_signature", "rsa_encrypt_file", 
    "rsa_decrypt_file", "VaultAPI", "MySQLAPI", "SSH", "SFTP", "SMTPAPI", "is_type", "is_bytes", 
    "is_str", "is_int", "is_float", "is_bool", "is_list", "is_dict", "is_tuple", "is_path", 
    "is_net_ok", "random_hex"
]


__version__ = "1.1.0.rc1"
TYPE_NAME = "module"
NAME = "mlcbase"
DESCRIPTION = "The base module of all MuLingCloud modules and applications."


if not hasattr(__import__(NAME), NAME):
    from colorama import Fore
    
    print(f"\n👋 {Fore.BLUE}Welcome to use {Fore.RED}MuLingCloud{Fore.BLUE}. "
          f"We aim to let everything easier.{Fore.BLUE}\n\n"
          f"📍 {Fore.YELLOW}{NAME} ({__version__}) imported{Fore.RESET}\n")

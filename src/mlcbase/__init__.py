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

from .conifg import ConfigDict, is_config_dict
from .logger import Logger
from .timer import wrap_module_timer, delete_register_modules, show_register_modules, runtime_analysis
from .emoji_pbar import EmojiProgressBar
from .file import create, remove, listdir, get_file_size, get_dir_size, get_meta_info
from .loading import load_json, save_json, load_yaml, save_yaml, load_xml, save_xml, load_toml, save_toml
from .image_io import get_image_from_url, load_image, save_image
from .encrypt_password import encrypt_password, verify_password
from .entrypt_aes import aes_encrypt_text, aes_decrypt_text, aes_entrypt_file, aes_decrypt_file
from .entrypt_rsa import (create_rsa_keys, rsa_encrypt_text, rsa_decrypt_text, rsa_sign_text,
                          rsa_verify_signature, rsa_encrypt_file, rsa_decrypt_file)
from .otp import generate_otp_secret, generate_otp_code, verify_otp_code
from .vault import (VaultDuration, VaultSecretEngineKV1, VaultSecretEngineKV2, VaultSecretEngineTOTP, 
                    VaultSecretEngineTransit)
from .database import MySQLAPI, SQLiteAPI
from .remote_connect import SSH, SFTP
from .email import SMTPAPI
from .register import Registry, DATABASE, EMAIL, SECRET, FILEOPT, IMAGEIO, REMOTE
from .misc import (is_type, is_bytes, is_str, is_int, is_float, is_bool, is_list, is_dict,
                   is_tuple, is_path, is_url, is_base64, random_hex, random_otp_secret, get_net_info,
                   is_canonical_version, parse_version)

__all__ = [
    # config
    "ConfigDict", "is_config_dict", 

    # logger
    "Logger", 

    # timer
    "wrap_module_timer", "delete_register_modules", "show_register_modules", "runtime_analysis", 

    # emoji_pbar
    "EmojiProgressBar", 
    
    # file
    "create", "remove", "listdir", "get_file_size", "get_dir_size", "get_meta_info", 
    
    # loading
    "load_json", "save_json", "load_yaml", "save_yaml", "load_xml", "save_xml", "load_toml", "save_toml",

    # image_io
    "get_image_from_url", "load_image", "save_image", 
    
    # encrypt_password
    "encrypt_password", "verify_password", 
    
    # entrypt_aes
    "aes_encrypt_text", "aes_decrypt_text", "aes_entrypt_file", "aes_decrypt_file", 
    
    # entrypt_rsa
    "create_rsa_keys", "rsa_encrypt_text", "rsa_decrypt_text", "rsa_sign_text", "rsa_verify_signature", "rsa_encrypt_file", 
    "rsa_decrypt_file", 

    # otp
    "generate_otp_secret", "generate_otp_code", "verify_otp_code", 
    
    # vault
    "VaultDuration", "VaultSecretEngineKV1", "VaultSecretEngineKV2", "VaultSecretEngineTOTP", "VaultSecretEngineTransit", 
    
    # database
    "MySQLAPI", "SQLiteAPI", 

    # remote_connect
    "SSH", "SFTP", 
    
    # email
    "SMTPAPI", 
    
    # register
    "Registry", "DATABASE", "EMAIL", "SECRET", "FILEOPT", "IMAGEIO", "REMOTE", 
    
    # misc
    "is_type", "is_bytes", "is_str", "is_int", "is_float", "is_bool", "is_list", "is_dict", "is_tuple", "is_path", "is_url", 
    "is_base64", "random_hex", "random_otp_secret", "get_net_info", "is_canonical_version", "parse_version"
]


__version__ = "1.2.5"
TYPE_NAME = "module"
NAME = "mlcbase"
DESCRIPTION = "The base module of all MuLingCloud modules and applications."


if not hasattr(__import__(NAME), NAME):
    from colorama import Fore
    
    hello_msg = f"\n👋 {Fore.BLUE}Welcome to use {Fore.RED}MuLingCloud{Fore.BLUE}. We aim to let everything easier.{Fore.BLUE}\n\n📍 {Fore.YELLOW}{NAME} ({__version__}) imported{Fore.RESET}\n"
    print(hello_msg.encode("utf-8").decode("utf-8"))

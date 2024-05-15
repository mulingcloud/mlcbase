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
MuLingCloud base module: password encryption

Author: Weiming Chen
Tester: Weiming Chen
"""
import hashlib
from typing import List, Union

from .register import SECRET
from .misc import is_str, is_list

support_methods = {'MD5': hashlib.md5,
                   'SHA-1': hashlib.sha1,
                   'SHA-224': hashlib.sha224,
                   'SHA-256': hashlib.sha256,
                   'SHA-384': hashlib.sha384,
                   'SHA-512': hashlib.sha512}


@SECRET.register_module()
def encrypt_password(password: str, 
                     methods: Union[str, List[str]], 
                     encoding: str = "utf-8"):
    """encrypt password following the order of __encrypt_method

    Args:
        password (str)
        methods (Union[str, List[str]])
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        str: cipher
    """
    assert is_str(password), "password must be a string"
    assert is_str(methods) or is_list(methods), "methods must be a string or a list"
    
    if is_str(methods):
        methods = [methods]

    cipher = password
    for method in methods:
        cipher = support_methods[method](cipher.encode(encoding)).hexdigest()

    return cipher


@SECRET.register_module()
def verify_password(password: str, 
                    cipher: str, 
                    methods: Union[str, List[str]], 
                    encoding: str = "utf-8"):
    """verify if the password match with the cipher

    Args:
        password (str)
        cipher (str)
        methods (Union[str, List[str]])
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        bool: return True if the password match with the cipher, otherwise return False
    """
    if cipher == encrypt_password(password, methods, encoding):
        return True
    else:
        return False

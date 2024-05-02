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
MuLingCloud base module: miscellaneous features

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import re
import warnings
import random
import base64
import requests
from pathlib import Path
from typing import Optional


def is_type(p):
    if isinstance(p, type):
        return True
    else:
        return False
    

def is_bytes(p):
    if isinstance(p, bytes):
        return True
    else:
        return False


def is_str(p):
    if isinstance(p, str):
        return True
    else:
        return False


def is_int(p):
    if isinstance(p, int):
        return True
    else:
        return False


def is_float(p):
    if isinstance(p, float):
        return True
    else:
        return False


def is_bool(p):
    if isinstance(p, bool):
        return True
    else:
        return False


def is_list(p):
    if isinstance(p, list):
        return True
    else:
        return False


def is_dict(p):
    if isinstance(p, dict):
        return True
    else:
        return False


def is_tuple(p):
    if isinstance(p, tuple):
        return True
    else:
        return False


def is_path(p):
    if isinstance(p, Path):
        return True
    else:
        return False
    

def is_url(url: str, 
           test_connection: bool = True, 
           timeout: int = 3):
    pattern = re.compile(r'^(https?://)?'                                   # http or https
                         r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'  # domain name
                         r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'             # domain name suffix
                         r'localhost|'                                      # local host
                         r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'             # IP address
                         r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'                     # IPv6
                         r'(?::\d+)?'                                       # port number
                         r'(?:/?|[/?]\S+)$', re.IGNORECASE)                 # path
    matched_url = re.match(pattern, url)

    if test_connection:
        if matched_url is not None:
            try:
                response = requests.get(url, timeout=timeout)
                if response.status_code < 400:
                    return True
                else:
                    return False
            except ConnectionError:
                return False
        else:
            return False
    else:
        if matched_url is not None:
            return True
        else:
            return False
        

def is_base64(s):
    if not (is_str(s) or is_bytes(s)):
        return False
    
    try:
        base64.b64decode(s)
        return True
    except:
        return False
            

def random_hex(length: int, seed: Optional[int] = None, uppercase: bool = True):
    """generate a random hex string

    Args:
        length (int): the length of the string
        seed (Optional[int], optional): random seed. Defaults to None.
        uppercase (bool, optional): if True, the string will be uppercase. 
                                    Defaults to True.

    Returns:
        str: hex string
    """
    if is_int(seed):
        random.seed(seed)
    
    charset = "0123456789ABCDEF"
    if uppercase:
        result = [random.choice(charset) for _ in range(length)]
    else:
        result = [random.choice(charset).lower() for _ in range(length)]
        
    return ''.join(result)


def random_otp_secret(length: int = 32, 
                      seed: Optional[int] = None,
                      uppercase: bool = True):
    """generate a random OTP secret key

    Args:
        length (int, optional): the length of the secret key. Defaults to 32.
        seed (Optional[int], optional): random seed. Defaults to None.
        uppercase (bool, optional): if True, the string will be uppercase. 
                                    Defaults to True.

    Raises:
        ValueError: raise ValueError if the length of the OTP secret key is less 
                    than 32 or not divisible by 8

    Returns:
        str: secret key
    """
    if length < 32:
        raise ValueError("The length of the OTP secret key must be at least 32")
    if length % 8 != 0:
        raise ValueError("The length of the OTP secret key must be divisible by 8")
    
    if is_int(seed):
        random.seed(seed)
    
    charset = "234567ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if uppercase:
        result = [random.choice(charset) for _ in range(length)]
    else:
        result = [random.choice(charset).lower() for _ in range(length)]
        
    return ''.join(result)


class VersionMisMatchError(ValueError):
    ...
    

class VersionNotSupportError(ValueError):
    ...


class VersionNotFoundError(ValueError):
    ...
    
    
class NewVersionAvailableWarning:
    def __init__(self, message: str):
        warnings.warn(message)
    

class PlatformNotSupportError(OSError):
    ...


class FileTooLargeError(OSError):
    ...


class FileUploadError(OSError):
    ...

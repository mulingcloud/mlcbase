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
MuLingCloud base module: miscellaneous

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import warnings
import random
from pathlib import Path
from typing import Optional
from socket import socket


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


def is_net_ok():
    """Test if the internet connection is ok
    
    Returns:
        bool: return True if the internet connection is ok, otherwise return False
    """
    s = socket()
    s.settimeout(3)
    try:
        status = s.connect_ex(("www.baidu.com", 443))
        if status == 0:
            s.close()
            return True
        else:
            return False
    except:
        return False
            

def random_hex(length: int, seed: Optional[int] = None):
    """generate a random hex string

    Args:
        length (int): the length of the string
        seed (Optional[int], optional): random seed. Defaults to None.

    Returns:
        str: hex string
    """
    if is_int(seed):
        random.seed(seed)
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))


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

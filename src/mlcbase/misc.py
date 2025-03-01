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
import ipaddress
import warnings
import random
import base64
import socket
import platform
from pathlib import Path
from typing import Optional

import requests
import psutil
from packaging.version import parse

from .conifg import ConfigDict
from .logger import Logger


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


def is_squence(p):
    if is_list(p) or is_tuple(p):
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
        result = random.choices(charset, k=length)
    else:
        result = random.choices(charset.lower(), k=length)
        
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


def get_net_info(name: Optional[str] = None, logger: Optional[Logger] = None):
    try:
        hostname = socket.gethostname()
        net_info = ConfigDict(hostname=hostname)
        if name is None:
            ip_addr = ipaddress.ip_address(socket.gethostbyname(hostname))
            for k, v in psutil.net_if_addrs().items():
                for addr in v:
                    if addr.address == ip_addr.compressed:
                        name = k
                        break
                if name is not None:
                    break
        addr_info = psutil.net_if_addrs()[name]
        for addr in addr_info:
            if addr.family == psutil.AF_LINK:
                net_info.mac = addr.address
            else:
                ip = ipaddress.ip_address(addr.address)
                if ip.version == 4:
                    net_info.ip = ip.compressed
                elif ip.version == 6:
                    if ip.is_global:
                        net_info.ipv6 = ip.compressed
                    if ip.is_private:
                        net_info.ipv6_private = ip.compressed
        return net_info
    except Exception as e:
        if logger is not None:
            logger.error(f"Failed to get network info: {str(e)}")
        else:
            print(f"Failed to get network info: {str(e)}")
        return None


def is_canonical_version(version):
    return re.match(r'^([1-9][0-9]*!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?$', version) is not None


def parse_version(version):
    if not is_canonical_version(version):
        raise ValueError(f'The version {version} identifier is not in the canonical format')
    
    return parse(version)


def path_join(*args, os_type: str = "auto"):
    path_list = []
    for i, p in enumerate(args):
        if not is_str(p):
            raise TypeError(f"Path must be a string, but got {type(p)}")
        
        p = p.strip()
        if i == 0:
            if p.endswith("/") or p.endswith("\\"):
                p = p[:-1]
        else:
            p = p.strip("/").strip("\\")
        path_list.append(p)
    
    os_type = platform.system().lower() if os_type == "auto" else os_type
    if os_type == "windows":
        return "\\".join(path_list)
    else:
        return "/".join(path_list)


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

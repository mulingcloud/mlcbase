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
MuLingCloud base module: AES encryption and decryption

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
from pathlib import Path
from typing import Union, Optional

from Crypto.Cipher import AES

from .logger import Logger
from .register import SECRET
from .misc import is_str, is_bytes

PathLikeType = Union[str, Path]


def __completion(conent: Union[str, bytes], encoding: str = "utf-8"):
    assert is_str(conent) or is_bytes(conent), 'conent must be str or bytes'

    if is_str(conent):
        conent = conent.encode(encoding)
    
    while len(conent) % 16 != 0:
        conent += b'\x00'
    
    return conent


@SECRET.register_module()
def aes_encrypt_text(plain_text: Union[str, bytes],
                     key: Union[str, bytes],
                     iv: Optional[Union[str, bytes]] = None,
                     mode: int = AES.MODE_CBC,
                     encoding: str = "utf-8"):
    """encrypt plain text with aes

    Args:
        plain_text (str)
        key (Union[str, bytes])
        iv (Optional[Union[str, bytes]], optional): Defaults to None.
        mode (int, optional): Defaults to AES.MODE_CBC.
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        bytes: cipher text
    """
    assert is_str(key) or is_bytes(key), 'key must be str or bytes'
    assert len(key) in [16, 24, 32], 'the length of key must be 16, 24 or 32'
    assert iv is None or ((is_str(iv) or is_bytes(iv)) and len(iv) == 16), \
        'when iv is not None, iv must be str or bytes, and the length of iv should be 16'
    assert mode in [AES.MODE_CBC, AES.MODE_ECB], 'currently only support AES.MODE_CBC or AES.MODE_ECB mode'

    key = key.encode(encoding) if is_str(key) else key
    if iv is not None:
        iv = iv.encode(encoding) if is_str(iv) else iv

    plain_text = __completion(plain_text, encoding)
    
    if mode == AES.MODE_CBC:
        assert iv is not None, 'iv must be provided when using AES.MODE_CBC mode'
        cipher_text = AES.new(key, mode, iv).encrypt(plain_text)

    if mode == AES.MODE_ECB:
        cipher_text = AES.new(key, mode).encrypt(plain_text)

    return cipher_text


@SECRET.register_module()
def aes_decrypt_text(cipher_text: bytes,
                     key: Union[str, bytes],
                     iv: Optional[Union[str, bytes]] = None,
                     mode: int = AES.MODE_CBC,
                     return_str: bool = True,
                     encoding: str = "utf-8"):
    """decrypt cipher text with aes

    Args:
        cipher_text (bytes)
        key (Union[str, bytes])
        iv (Optional[Union[str, bytes]], optional): Defaults to None.
        mode (int, optional): Defaults to AES.MODE_CBC.
        return_str (bool, optional): return a string if True, otherwise return a bytes.
                                     Defaults to True.
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        str or bytes: return a string if return_str is True, otherwise return a bytes
    """
    assert is_str(key) or is_bytes(key), 'key must be str or bytes'
    assert len(key) in [16, 24, 32], 'the length of key must be 16, 24 or 32'
    assert iv is None or ((is_str(iv) or is_bytes(iv)) and len(iv) == 16), \
        'when iv is not None, iv must be str or bytes, and the length of iv should be 16'
    assert mode in [AES.MODE_CBC, AES.MODE_ECB], 'currently only support AES.MODE_CBC or AES.MODE_ECB mode'

    key = key.encode(encoding) if is_str(key) else key
    if iv is not None:
        iv = iv.encode(encoding) if is_str(iv) else iv
    
    if mode == AES.MODE_CBC:
        assert iv is not None, 'iv must be provided when using AES.MODE_CBC mode'
        plain_text = AES.new(key, mode, iv).decrypt(cipher_text)
    
    if mode == AES.MODE_ECB:
        plain_text = AES.new(key, mode).decrypt(cipher_text)

    plain_text = plain_text.strip(b'\x00')
    if return_str:
        plain_text = plain_text.decode(encoding)

    return plain_text


@SECRET.register_module()
def aes_entrypt_file(plain_file_path: PathLikeType,
                     crypto_save_path: PathLikeType,
                     key: Union[str, bytes],
                     iv: Optional[Union[str, bytes]] = None,
                     mode: int = AES.MODE_CBC,
                     encoding: str = "utf-8",
                     logger: Optional[Logger] = None):
    """encrypt plain file with aes

    Args:
        plain_file_path (PathLikeType)
        crypto_save_path (PathLikeType)
        key (Union[str, bytes])
        iv (Optional[Union[str, bytes]], optional): Defaults to None.
        mode (int, optional): Defaults to AES.MODE_CBC.
        encoding (str, optional): Defaults to "utf-8".
        logger (Optional[Logger], optional): Defaults to None.
    
    Returns:
        bool: True if success, otherwise False
    """
    assert Path(plain_file_path).exists(), f"No such file: {plain_file_path}"
    assert crypto_save_path.endswith(".bin"), "Crypto file must be a .bin file"

    try:
        with open(plain_file_path, 'rb') as fp, open(crypto_save_path, 'wb') as fc:
            cipher_text = aes_encrypt_text(fp.read(), key, iv, mode, encoding)
            fc.write(cipher_text)
            
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'aes encrypt file error: {str(e)}')
        return False


@SECRET.register_module()
def aes_decrypt_file(crypto_file_path: PathLikeType, 
                     plain_save_path: PathLikeType,
                     key: Union[str, bytes],
                     iv: Optional[Union[str, bytes]] = None,
                     mode: int = AES.MODE_CBC,
                     encoding: str = "utf-8",
                     logger: Optional[Logger] = None):
    """decrypt crypto file with aes

    Args:
        crypto_file_path (PathLikeType)
        plain_save_path (PathLikeType)
        key (Union[str, bytes])
        iv (Optional[Union[str, bytes]], optional): Defaults to None.
        mode (int, optional): Defaults to AES.MODE_CBC.
        encoding (str, optional): Defaults to "utf-8".
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: True if success, otherwise False
    """
    assert Path(crypto_file_path).exists(), f"No such file: {crypto_file_path}"

    try:
        with open(crypto_file_path, 'rb') as fc:
            plain_text = aes_decrypt_text(fc.read(), key, iv, mode, False, encoding)

        if plain_save_path is not None:
            with open(plain_save_path, 'wb') as fp:
                fp.write(plain_text)

        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'aes decrypt file error: {str(e)}')
        return False

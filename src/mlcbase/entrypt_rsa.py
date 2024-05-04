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
MuLingCloud base module: RSA encryption and decryption

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import multiprocessing as mp
from pathlib import Path
from threading import Thread
from typing import Optional, Union, List

import rsa

from .logger import Logger
from .file import get_file_size
from .misc import is_list, is_bytes, is_str, is_path, is_int

PathLikeType = Union[str, Path]


class _EncryptTextThread(Thread):
    def __init__(self, plain_text, public_key, key_length):
        Thread.__init__(self)
        self.plain_text = plain_text
        self.public_key = public_key
        self.key_length = key_length
        self.cipher_text = None

    def run(self):
        default_length = self.key_length // 8 - 11
        if len(self.plain_text) <= default_length:
            cipher_text = rsa.encrypt(self.plain_text, self.public_key)
        else:
            offset = 0
            cipher_text = []
            while len(self.plain_text) - offset > 0:
                if len(self.plain_text) - offset > default_length:
                    cipher_text.append(rsa.encrypt(self.plain_text[offset:offset + default_length], self.public_key))
                else:
                    cipher_text.append(rsa.encrypt(self.plain_text[offset:], self.public_key))
                offset += default_length
        self.cipher_text = cipher_text


class _DecryptTextThread(Thread):
    def __init__(self, cipher_text, private_key, encoding, return_str, key_length):
        Thread.__init__(self)
        self.cipher_text = cipher_text
        self.private_key = private_key
        self.encoding = encoding
        self.return_str = return_str
        self.key_length = key_length
        self.plain_text = None

    def run(self):
        if is_list(self.cipher_text):
            if self.return_str:
                plain_text = ""
            else:
                plain_text = b""

            for c in self.cipher_text:
                if self.return_str:
                    plain_text += rsa.decrypt(c, self.private_key).decode(self.encoding)
                else:
                    plain_text += rsa.decrypt(c, self.private_key)
        
        if is_bytes(self.cipher_text):
            length = len(self.cipher_text)
            chunk_length = self.key_length // 8
            if length > chunk_length:
                offset = 0
                if self.return_str:
                    plain_text = ""
                else:
                    plain_text = b""

                while length - offset > 0:
                    if length - offset > chunk_length:
                        if self.return_str:
                            plain_text += rsa.decrypt(self.cipher_text[offset:offset+chunk_length], self.private_key).decode(self.encoding)
                        else:
                            plain_text += rsa.decrypt(self.cipher_text[offset:offset+chunk_length], self.private_key)
                    else:
                        if self.return_str:
                            plain_text += rsa.decrypt(self.cipher_text[offset:], self.private_key).decode(self.encoding)
                        else:
                            plain_text += rsa.decrypt(self.cipher_text[offset:], self.private_key)
                    offset += chunk_length
            else:
                if self.return_str:
                    plain_text = rsa.decrypt(self.cipher_text, self.private_key).decode(self.encoding)
                else:
                    plain_text = rsa.decrypt(self.cipher_text, self.private_key)
        
        self.plain_text = plain_text


def create_rsa_keys(public_path: Optional[PathLikeType] = None, 
                    private_path: Optional[PathLikeType] = None, 
                    key_length: int = 2048,
                    return_keys: bool = False):
    """create a pair of rsa keys

    Args:
        public_path (Optional[PathLikeType], optional): Defaults to None.
        private_path (Optional[PathLikeType], optional): Defaults to None.
        key_length (int, optional): We force the length of key must be larger or equal to 2048 for safety resons. 
                                    Common options including 2048, 3072, and 4096. Defaults to 2048.
        return_keys (bool, optional): Defaults to False.

    Returns:
        tuple or None: return a pair of rsa keys if return_keys is True, otherwise return None
    """
    assert key_length >= 2048, "Force the key_length must be larger or equal to 2048 for safety resons"
    assert key_length % 8 == 0, "The length of secret key must be a multiple of 8"
    assert (public_path is not None and private_path is not None) or return_keys, \
        "public_path and private_path must be provided if return_keys is False"

    (public_key, private_key) = rsa.newkeys(key_length)
    public_key = public_key.save_pkcs1("PEM")
    private_key = private_key.save_pkcs1("PEM")
    if public_path and private_path:
        assert public_path.endswith(".pem"), "public key file must be a PEM file"
        assert private_path.endswith(".pem"), "private key file must be a PEM file"

        with open(public_path, "wb+") as f:
            f.write(public_key)
        with open(private_path, "wb+") as f:
            f.write(private_key)
    
    if return_keys:
        return (public_key, private_key)
    else:
        return None


def rsa_encrypt_text(plain_text: Union[str, bytes], 
                     public_key: Union[bytes, PathLikeType], 
                     key_length: int = 2048,
                     num_threads: int = 1,
                     encoding: str = "utf-8"):
    """encrypt plain text with rsa public key

    Args:
        plain_text (Union[str, bytes])
        public_key (Union[bytes, PathLikeType)
        key_length (int, optional): Defaults to 2048.
        num_threads (int, optional): thread numbers to use, which is larger or equal to 1. 
                                     Defaults to 1.
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        bytes or List[bytes]: cipher_text
    """
    assert key_length % 8 == 0, "The length of secret key must be a multiple of 8"
    assert is_str(plain_text) or is_bytes(plain_text), "plain_text must be a string or bytes"
    assert is_str(public_key) or is_path(public_key) or is_bytes(public_key), \
        "public_key must be a bytes or a path"

    # load public key
    if is_str(public_key) or is_path(public_key):
        with open(public_key, "rb") as f:
            key = rsa.PublicKey.load_pkcs1(f.read())
    else:
        key = rsa.PublicKey.load_pkcs1(public_key)
    
    if is_str(plain_text):
        plain_text = plain_text.encode(encoding)
    
    # split plain_text into multiple threads
    if num_threads > 1:
        length = len(plain_text) // num_threads
        threads = []
        for i in range(num_threads):
            if i < num_threads - 1:
                thread = _EncryptTextThread(plain_text[i * length:(i + 1) * length], key, key_length)
            else:
                thread = _EncryptTextThread(plain_text[i * length:], key, key_length)
            threads.append(thread)
            thread.start()

        cipher_text = []
        for thread in threads:
            thread.join()
            if is_list(thread.cipher_text):
                cipher_text.extend(thread.cipher_text)
            if is_bytes(thread.cipher_text):
                cipher_text.append(thread.cipher_text)
    else:
        default_length = key_length // 8 - 11
        if len(plain_text) <= default_length:
            cipher_text = rsa.encrypt(plain_text, key)
        else:
            offset = 0
            cipher_text = []
            while len(plain_text) - offset > 0:
                if len(plain_text) - offset > default_length:
                    cipher_text.append(rsa.encrypt(plain_text[offset:offset+default_length], key))
                else:
                    cipher_text.append(rsa.encrypt(plain_text[offset:], key))
                offset += default_length
    
    return cipher_text


def rsa_decrypt_text(cipher_text: Union[List[bytes], bytes],
                     private_key: Union[bytes, PathLikeType],
                     key_length: int = 2048,
                     num_threads: int = 1,
                     return_str: bool = True,
                     encoding: str = "utf-8",):
    """decrypt cipher text with rsa private key

    Args:
        cipher_text (Union[List[bytes], bytes])
        private_key (Union[bytes, PathLikeType])
        key_length (int, optional): Defaults to 2048.
        num_threads (int, optional): thread numbers to use, which is larger or equal to 1. 
                                    Defaults to 1.
        return_str (bool, optional): return a string if True, otherwise return a bytes.
                                     Defaults to True.
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        str or bytes: return a string if return_str is True, otherwise return a bytes
    """
    assert key_length % 8 == 0, "The length of secret key must be a multiple of 8"
    assert is_list(cipher_text) or is_bytes(cipher_text), "cipher_text must be a list or bytes"
    assert is_str(private_key) or is_path(private_key) or is_bytes(private_key), \
        "private_key must be a bytes or a path"

    # load private key
    if is_str(private_key) or is_path(private_key):
        with open(private_key, "rb") as f:
            key = rsa.PrivateKey.load_pkcs1(f.read())
    else:
        key = rsa.PrivateKey.load_pkcs1(private_key)

    # split cipher_text into multiple threads
    if num_threads > 1:
        length = len(cipher_text) // num_threads
        threads = []
        for i in range(num_threads):
            if i < num_threads - 1:
                thread = _DecryptTextThread(cipher_text[i*length:(i+1)*length], key, encoding, return_str, key_length)
            else:
                thread = _DecryptTextThread(cipher_text[i*length:], key, encoding, return_str, key_length)
            threads.append(thread)
            thread.start()
            
        if return_str:
            plain_text = ""
        else:
            plain_text = b""
            
        for thread in threads:
            thread.join()
            plain_text += thread.plain_text
    else:
        if is_list(cipher_text):
            if return_str:
                plain_text = ""
            else:
                plain_text = b""
                
            for c in cipher_text:
                if return_str:
                    plain_text += rsa.decrypt(c, key).decode(encoding)
                else:
                    plain_text += rsa.decrypt(c, key)
        
        if is_bytes(cipher_text):
            length = len(cipher_text)
            chunk_length = key_length // 8
            if length > chunk_length:
                offset = 0
                if return_str:
                    plain_text = ""
                else:
                    plain_text = b""

                while length - offset > 0:
                    if length - offset > chunk_length:
                        if return_str:
                            plain_text += rsa.decrypt(cipher_text[offset:offset+chunk_length], key).decode(encoding)
                        else:
                            plain_text += rsa.decrypt(cipher_text[offset:offset+chunk_length], key)
                    else:
                        if return_str:
                            plain_text += rsa.decrypt(cipher_text[offset:], key).decode(encoding)
                        else:
                            plain_text += rsa.decrypt(cipher_text[offset:], key)
                    offset += chunk_length
            else:
                if return_str:
                    plain_text = rsa.decrypt(cipher_text, key).decode(encoding)
                else:
                    plain_text = rsa.decrypt(cipher_text, key)
        
    return plain_text


def rsa_sign_text(plain_text: str,
                  private_key: Union[bytes, PathLikeType],
                  hash_method: str = "SHA-512",
                  encoding: str = "utf-8"):
    """sign plain text with rsa private key

    Args:
        plain_text (str)
        private_key (Union[bytes, PathLikeType])
        hash_method (str, optional): Defaults to 'SHA-512'.
        encoding (str, optional): Defaults to "utf-8".
        
    Returns:
        bytes: signed cipher text
    """
    assert is_str(plain_text), "plain_text must be a string"
    assert is_str(private_key) or is_path(private_key) or is_bytes(private_key), \
        "private_key must be a bytes or a path"
    assert hash_method in ['MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512']

    if is_str(private_key) or is_path(private_key):
        with open(private_key, "rb") as f:
            key = rsa.PrivateKey.load_pkcs1(f.read())
    else:
        key = rsa.PrivateKey.load_pkcs1(private_key)
    
    signed_cipher_text = rsa.sign(plain_text.encode(encoding), key, hash_method)

    return signed_cipher_text


def rsa_verify_signature(plain_text: str,
                         signature: bytes,
                         public_key: Union[bytes, PathLikeType],
                         encoding: str = "utf-8"):
    """verify signature with rsa public key

    Args:
        plain_text (str)
        signature (bytes)
        public_key (Union[bytes, PathLikeType])
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        bool: return True if the signature match the plain text, otherwise return False
    """
    assert is_str(plain_text), "plain_text must be a string"
    assert is_bytes(signature), "signed_cipher_text must be a bytes"
    
    if is_str(public_key) or is_path(public_key):
        with open(public_key, "rb") as f:
            key = rsa.PublicKey.load_pkcs1(f.read())
    else:
        key = rsa.PublicKey.load_pkcs1(public_key)

    try:
        rsa.verify(plain_text.encode(encoding), signature, key)
        return True
    except:
        return False


def rsa_encrypt_file(plain_file_path: PathLikeType, 
                     crypto_save_path: PathLikeType, 
                     public_key: Union[bytes, PathLikeType], 
                     key_length: int = 2048,
                     num_process: int = 1,
                     num_threads: int = 1,
                     encoding: str = "utf-8",
                     logger: Optional[Logger] = None):
    """encrypt file with rsa public key

    Args:
        plain_file_path (PathLikeType)
        crypto_save_path (PathLikeType)
        public_key (Union[bytes, PathLikeType])
        key_length (int, optional): Defaults to 2048.
        num_process (int, optional): number of processes. Defaults to 1.
        num_threads (int, optional): number of threads. Defaults to 1.
        encoding (str, optional): Defaults to "utf-8".
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if the file is encrypted successfully, otherwise return False
    """
    assert Path(plain_file_path).exists(), f"No such file: {plain_file_path}"
    assert crypto_save_path.endswith(".bin"), "Crypto file must be a .bin file"
    assert is_str(public_key) or is_path(public_key) or is_bytes(public_key), \
        "public_key must be a bytes or a path"
    assert is_int(num_process) and num_process > 0, "num_process must be a positive integer"
    assert num_process <= mp.cpu_count(), "num_process must be less than or equal to the number of CPU cores"
    assert num_process == 1 or num_process % 2 == 0, "num_process must be an even number"
    assert is_int(num_threads) and num_threads > 0, "num_threads must be a positive integer"

    try:
        if num_process > 1:
            # chunk large file
            file_size = get_file_size(plain_file_path, auto_unit=False)[0]
            chunk_size = file_size // num_process + 1
            with open(plain_file_path, "rb") as f:
                cnt = 0
                while True:
                    chunk = f.read(chunk_size)
                    
                    if chunk:
                        with open(str(plain_file_path)+f".chunk.{cnt}", "wb") as f_chunk:
                            f_chunk.write(chunk)
                        cnt += 1
                    else:
                        break

            # encrypt
            pool = mp.Pool(num_process)
            cipher_list = []
            for i in range(num_process):
                with open(str(plain_file_path)+f".chunk.{i}", "rb") as f_chunk:
                    chunk = f_chunk.read()
                    cihper = pool.apply_async(rsa_encrypt_text, args=(chunk, public_key, key_length, num_threads, encoding,))
                    cipher_list.append(cihper)
                Path(str(plain_file_path)+f".chunk.{i}").unlink()
            pool.close()
            pool.join()
        else:
            with open(plain_file_path, "rb") as f_chunk:
                chunk = f_chunk.read()
                cipher_list = rsa_encrypt_text(chunk, public_key, key_length, num_threads, encoding)
                if is_bytes(cipher_list):
                    cipher_list = [cipher_list]
        
        # save
        with open(crypto_save_path, "wb") as f_save:
            for cipher in cipher_list:
                if num_process > 1:
                    cipher_text = cipher.get()
                else:
                    cipher_text = cipher

                if is_list(cipher_text):
                    for c in cipher_text:
                        f_save.write(c)
                else:
                    f_save.write(cipher_text)
                    
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'rsa encrypt file error: {str(e)}')
        return False


def rsa_decrypt_file(crypto_file_path: PathLikeType,
                     plain_save_path: PathLikeType,
                     private_key: Union[bytes, PathLikeType],
                     key_length: int = 2048,
                     num_process: int = 1,
                     num_threads: int = 1,
                     encoding: str = "utf-8",
                     logger: Optional[Logger] = None):
    """decrypt file with rsa private key

    Args:
        crypto_file_path (PathLikeType)
        plain_save_path (PathLikeType)
        private_key (Union[bytes, PathLikeType])
        key_length (int, optional): Defaults to 2048.
        num_process (int, optional): number of processes. Defaults to 1.
        num_threads (int, optional): number of threads. Defaults to 1.
        encoding (str, optional): Defaults to "utf-8".
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if the file is decrypted successfully, otherwise return False
    """
    assert crypto_file_path.endswith(".bin"), "Crypto file must be a .bin file"
    assert is_str(private_key) or is_path(private_key) or is_bytes(private_key), \
        "private_key must be a bytes or a path"
    assert is_int(num_process) and num_process > 0, "num_process must be a positive integer"
    assert num_process <= mp.cpu_count(), "num_process must be less than or equal to the number of CPU cores"
    assert num_process == 1 or num_process % 2 == 0, "num_process must be an even number"
    assert is_int(num_threads) and num_threads > 0, "num_threads must be a positive integer"
    
    try:
        if num_process > 1:
            # chunk large file
            file_size = get_file_size(crypto_file_path, auto_unit=False)[0]
            chunk_size = int(file_size / num_process)
            with open(crypto_file_path, "rb") as f:
                cnt = 0
                while True:
                    chunk = f.read(chunk_size)
                    
                    if chunk:
                        with open(str(crypto_file_path)+f".chunk.{cnt}", "wb") as f_chunk:
                            f_chunk.write(chunk)
                        cnt += 1
                    else:
                        break
            
            # decrypt
            pool = mp.Pool(num_process)
            plain_list = []
            for i in range(num_process):
                with open(str(crypto_file_path)+f".chunk.{i}", "rb") as f_chunk:
                    chunk = f_chunk.read()
                    plain = pool.apply_async(rsa_decrypt_text, args=(chunk, private_key, key_length, num_threads, False, encoding, ))
                    plain_list.append(plain)
                Path(str(crypto_file_path)+f".chunk.{i}").unlink()
            pool.close()
            pool.join()
        else:
            with open(crypto_file_path, 'rb') as f_chunk:
                chunk = f_chunk.read()
                plain_list = [rsa_decrypt_text(chunk, private_key, key_length, num_threads, False, encoding)]
        
        # save
        with open(plain_save_path, "wb") as f_save:
            for plain in plain_list:
                if num_process > 1:
                    plain_text = plain.get()
                else:
                    plain_text = plain
                f_save.write(plain_text)
                    
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'rsa encrypt file error: {str(e)}')
        return False

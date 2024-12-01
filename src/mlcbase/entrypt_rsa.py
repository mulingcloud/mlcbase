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

Supported key format: PKCS#1, PKCS#8
Supported export format: PEM, DER
Supported hash algorithm: MD5, SHA1, SHA224, SHA256, SHA384, SHA512

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import base64
import multiprocessing as mp
from pathlib import Path
from threading import Thread
from typing import Optional, Union, List, Tuple, Any

from Crypto.PublicKey import RSA
from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.Cipher import PKCS1_v1_5 as pkcs1_cipher
from Crypto.Signature import PKCS1_v1_5 as pkcs1_signer

from .logger import Logger
from .file import get_file_size
from .register import SECRET
from .misc import is_list, is_bytes, is_str, is_path, is_int

PathLikeType = Union[str, Path]


class _EncryptTextThread(Thread):
    def __init__(self, plain_text, public_key, key_length, base64_encode):
        Thread.__init__(self)
        self.plain_text = plain_text
        self.public_key = public_key
        self.key_length = key_length
        self.base64_encode = base64_encode
        self.cipher_text = None

    def run(self):
        default_length = self.key_length // 8 - 11
        if len(self.plain_text) <= default_length:
            cipher_text = pkcs1_cipher.new(self.public_key).encrypt(self.plain_text)
            if self.base64_encode:
                cipher_text = base64.b64encode(cipher_text)
        else:
            offset = 0
            cipher_text = []
            while len(self.plain_text) - offset > 0:
                if len(self.plain_text) - offset > default_length:
                    sub_cipher_text = pkcs1_cipher.new(self.public_key).encrypt(self.plain_text[offset:offset+default_length])
                    if self.base64_encode:
                        sub_cipher_text = base64.b64encode(sub_cipher_text)
                    cipher_text.append(sub_cipher_text)
                else:
                    sub_cipher_text = pkcs1_cipher.new(self.public_key).encrypt(self.plain_text[offset:])
                    if self.base64_encode:
                        sub_cipher_text = base64.b64encode(sub_cipher_text)
                    cipher_text.append(sub_cipher_text)
                offset += default_length
        self.cipher_text = cipher_text


class _DecryptTextThread(Thread):
    def __init__(self, cipher_text, private_key, return_str, key_length, base64_decode, encoding, sentinel):
        Thread.__init__(self)
        self.cipher_text = cipher_text
        self.private_key = private_key
        self.return_str = return_str
        self.key_length = key_length
        self.encoding = encoding
        self.base64_decode = base64_decode
        self.sentinel = sentinel
        self.plain_text = None

    def run(self):
        if is_list(self.cipher_text):
            if self.return_str:
                plain_text = ""
            else:
                plain_text = b""

            for c in self.cipher_text:
                if self.base64_decode:
                    c = base64.b64decode(c)
                sub_plain_text = pkcs1_cipher.new(self.private_key).decrypt(c, self.sentinel)
                if self.return_str:
                    sub_plain_text = sub_plain_text.decode(self.encoding)
                plain_text += sub_plain_text
        
        if is_bytes(self.cipher_text):
            if self.base64_decode:
                self.cipher_text = base64.b64decode(self.cipher_text)
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
                        sub_plain_text = pkcs1_cipher.new(self.private_key).decrypt(self.cipher_text[offset:offset+chunk_length], self.sentinel)
                        if self.return_str:
                            sub_plain_text = sub_plain_text.decode(self.encoding)
                        plain_text += sub_plain_text
                    else:
                        sub_plain_text = pkcs1_cipher.new(self.private_key).decrypt(self.cipher_text[offset:], self.sentinel)
                        if self.return_str:
                            sub_plain_text = sub_plain_text.decode(self.encoding)
                        plain_text += sub_plain_text
                    offset += chunk_length
            else:
                plain_text = pkcs1_cipher.new(self.private_key).decrypt(self.cipher_text, self.sentinel)
                if self.return_str:
                    plain_text = plain_text.decode(self.encoding)
        
        self.plain_text = plain_text


@SECRET.register_module()
def create_rsa_keys(public_path: Optional[PathLikeType] = None, 
                    private_path: Optional[PathLikeType] = None, 
                    key_length: int = 2048,
                    key_format: str = "PKCS#1",
                    export_format: str = "PEM",
                    return_keys: bool = False) -> Union[Tuple[bytes, bytes], None]:
    """create a pair of rsa keys

    Args:
        public_path (Optional[PathLikeType], optional): Defaults to None.
        private_path (Optional[PathLikeType], optional): Defaults to None.
        key_length (int, optional): We force the length of key must be larger or equal to 2048 for safety resons. 
                                    Common options including 2048, 3072, and 4096. Defaults to 2048.
        key_format (str, optional): key format, options including "PKCS#1" and "PKCS#8". Defaults to "PKCS#1".
        export_format (str, optional): export format, options including "PEM" and "DER". Defaults to "PEM".
        return_keys (bool, optional): Defaults to False.

    Returns:
        tuple or None: return a pair of rsa keys (public_key, private_key) if return_keys is True, otherwise return None
    """
    assert key_format in ["PKCS#1", "PKCS#8"], "The key format must be PKCS#1 or PKCS#8"
    assert export_format in ["PEM", "DER"], "The export format must be PEM or DER"
    assert key_length >= 2048, "Force the key_length must be larger or equal to 2048 for safety resons"
    assert key_length % 8 == 0, "The length of secret key must be a multiple of 8"
    assert (public_path is not None and private_path is not None) or return_keys, \
        "public_path and private_path must be provided if return_keys is False"
    if public_path is not None or private_path is not None:
        if export_format != "PEM":
            raise ValueError("The export format must be PEM if public_path or private_path is provided")
    pkcs = 1 if key_format == "PKCS#1" else 8

    keys = RSA.generate(key_length)
    public_key = keys.public_key().export_key(format=export_format, pkcs=pkcs)
    private_key = keys.export_key(format=export_format, pkcs=pkcs)

    if public_path is not None:
        assert public_path.endswith(".pem"), "public key file must be a PEM file (.pem)"
        with open(public_path, "wb+") as f:
            f.write(public_key)
    if private_path is not None:
        assert private_path.endswith(".pem"), "private key file must be a PEM file (.pem)"
        with open(private_path, "wb+") as f:
            f.write(private_key)
    
    if return_keys:
        return (public_key, private_key)
    else:
        return None


@SECRET.register_module()
def rsa_encrypt_text(plain_text: Union[str, bytes], 
                     public_key: Union[bytes, PathLikeType], 
                     key_length: int = 2048,
                     num_threads: int = 1,
                     base64_encode: bool = True,
                     encoding: str = "utf-8") -> Union[bytes, List[bytes]]:
    """encrypt plain text with rsa public key

    Args:
        plain_text (Union[str, bytes])
        public_key (Union[bytes, PathLikeType)
        key_length (int, optional): Defaults to 2048.
        num_threads (int, optional): Thread numbers to use, which is larger or equal to 1. 
                                     Defaults to 1.
        base64_encode (bool, optional): Whether to encode the ciphertext with base64. Defaults to True.
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
            key = RSA.import_key(f.read())
    else:
        key = RSA.import_key(public_key)
    
    if is_str(plain_text):
        plain_text = plain_text.encode(encoding)
    
    # split plain_text into multiple threads
    if num_threads > 1:
        length = len(plain_text) // num_threads
        threads = []
        for i in range(num_threads):
            if i < num_threads - 1:
                thread = _EncryptTextThread(plain_text[i * length:(i + 1) * length], key, key_length, base64_encode)
            else:
                thread = _EncryptTextThread(plain_text[i * length:], key, key_length, base64_encode)
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
            cipher_text = pkcs1_cipher.new(key).encrypt(plain_text)
            if base64_encode:
                cipher_text = base64.b64encode(cipher_text)
        else:
            offset = 0
            cipher_text = []
            while len(plain_text) - offset > 0:
                if len(plain_text) - offset > default_length:
                    sub_cipher_text = pkcs1_cipher.new(key).encrypt(plain_text[offset:offset+default_length])
                    if base64_encode:
                        sub_cipher_text = base64.b64encode(sub_cipher_text)
                    cipher_text.append(sub_cipher_text)
                else:
                    sub_cipher_text = pkcs1_cipher.new(key).encrypt(plain_text[offset:])
                    if base64_encode:
                        sub_cipher_text = base64.b64encode(sub_cipher_text)
                    cipher_text.append(sub_cipher_text)
                offset += default_length
    
    return cipher_text


@SECRET.register_module()
def rsa_decrypt_text(cipher_text: Union[List[bytes], bytes],
                     private_key: Union[bytes, PathLikeType],
                     key_length: int = 2048,
                     num_threads: int = 1,
                     base64_decode: bool = True,
                     return_str: bool = True,
                     encoding: str = "utf-8",
                     sentinel: Any = 0) -> Union[str, bytes]:
    """decrypt cipher text with rsa private key

    Args:
        cipher_text (Union[List[bytes], bytes])
        private_key (Union[bytes, PathLikeType])
        key_length (int, optional): Defaults to 2048.
        num_threads (int, optional): thread numbers to use, which is larger or equal to 1. 
                                    Defaults to 1.
        base64_decode (bool, optional): Whether to decode the input ciphertext with base64. 
                                        Defaults to True.
        return_str (bool, optional): return a string if True, otherwise return a bytes.
                                     Defaults to True.
        encoding (str, optional): Defaults to "utf-8".
        sentinel (Any, optional): sentinel value for RSA decryption. Defaults to 0.

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
            key = RSA.import_key(f.read())
    else:
        key = RSA.import_key(private_key)

    # split cipher_text into multiple threads
    if num_threads > 1:
        length = len(cipher_text) // num_threads
        threads = []
        for i in range(num_threads):
            if i < num_threads - 1:
                thread = _DecryptTextThread(cipher_text[i*length:(i+1)*length], 
                                            key, 
                                            return_str, 
                                            key_length, 
                                            base64_decode, 
                                            encoding,
                                            sentinel)
            else:
                thread = _DecryptTextThread(cipher_text[i*length:], 
                                            key,  
                                            return_str, 
                                            key_length, 
                                            base64_decode, 
                                            encoding,
                                            sentinel)
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
                if base64_decode:
                    c = base64.b64decode(c)
                sub_plain_text = pkcs1_cipher.new(key).decrypt(c, sentinel)
                if return_str:
                    sub_plain_text = sub_plain_text.decode(encoding)
                plain_text += sub_plain_text
        
        if is_bytes(cipher_text):
            if base64_decode:
                cipher_text = base64.b64decode(cipher_text)
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
                        sub_plain_text = pkcs1_cipher.new(key).decrypt(cipher_text[offset:offset+chunk_length], sentinel)
                        if return_str:
                            sub_plain_text = sub_plain_text.decode(encoding)
                        plain_text += sub_plain_text
                    else:
                        sub_plain_text = pkcs1_cipher.new(key).decrypt(cipher_text[offset:], sentinel)
                        if return_str:
                            sub_plain_text = sub_plain_text.decode(encoding)
                        plain_text += sub_plain_text
                    offset += chunk_length
            else:
                plain_text = pkcs1_cipher.new(key).decrypt(cipher_text, sentinel)
                if return_str:
                    plain_text = plain_text.decode(encoding)
        
    return plain_text


@SECRET.register_module()
def rsa_sign_text(plain_text: str,
                  private_key: Union[bytes, PathLikeType],
                  hash_method: str = "SHA-512",
                  base64_encode: bool = True,
                  encoding: str = "utf-8") -> bytes:
    """sign plain text with rsa private key

    Args:
        plain_text (str)
        private_key (Union[bytes, PathLikeType])
        hash_method (str, optional): Defaults to 'SHA-512'.
        base64_encode (bool, optional): Whether to encode the signature with base64. Defaults to False.
        encoding (str, optional): Defaults to "utf-8".
        
    Returns:
        bytes: signature
    """
    assert is_str(plain_text), "plain_text must be a string"
    assert is_str(private_key) or is_path(private_key) or is_bytes(private_key), \
        "private_key must be a bytes or a path"
    hash_method = hash_method.replace("-", "")
    assert hash_method in ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']

    if is_str(private_key) or is_path(private_key):
        with open(private_key, "rb") as f:
            key = RSA.import_key(f.read())
    else:
        key = RSA.import_key(private_key)
    signer = pkcs1_signer.new(key)
    
    if hash_method == "MD5":
        digest = MD5.new()
    elif hash_method == "SHA1":
        digest = SHA1.new()
    elif hash_method == "SHA224":
        digest = SHA224.new()
    elif hash_method == "SHA256":
        digest = SHA256.new()
    elif hash_method == "SHA384":
        digest = SHA384.new()
    elif hash_method == "SHA512":
        digest = SHA512.new()
    digest.update(plain_text.encode(encoding))

    signature = signer.sign(digest)

    if base64_encode:
        signature = base64.b64encode(signature)

    return signature


@SECRET.register_module()
def rsa_verify_signature(plain_text: str,
                         signature: bytes,
                         public_key: Union[bytes, PathLikeType],
                         hash_method: str = "SHA-512",
                         base64_decode: bool = True,
                         encoding: str = "utf-8"):
    """verify signature with rsa public key

    Args:
        plain_text (str)
        signature (bytes)
        public_key (Union[bytes, PathLikeType])
        hash_method (str, optional): Defaults to 'SHA-512'.
        base64_decode (bool, optional): Whether to decode the signature with base64. Defaults to False.
        encoding (str, optional): Defaults to "utf-8".

    Returns:
        bool: return True if the signature match the plain text, otherwise return False
    """
    assert is_str(plain_text), "the plain text must be a string"
    assert is_bytes(signature), "the signature must be a bytes"
    hash_method = hash_method.replace("-", "")
    assert hash_method in ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']
    
    if is_str(public_key) or is_path(public_key):
        with open(public_key, "rb") as f:
            key = RSA.import_key(f.read())
    else:
        key = RSA.import_key(public_key)
    verifier = pkcs1_signer.new(key)

    if hash_method == "MD5":
        digest = MD5.new()
    elif hash_method == "SHA1":
        digest = SHA1.new()
    elif hash_method == "SHA224":
        digest = SHA224.new()
    elif hash_method == "SHA256":
        digest = SHA256.new()
    elif hash_method == "SHA384":
        digest = SHA384.new()
    elif hash_method == "SHA512":
        digest = SHA512.new()
    digest.update(plain_text.encode(encoding))

    if base64_decode:
        signature = base64.b64decode(signature)

    return verifier.verify(digest, signature)


@SECRET.register_module()
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
                    cihper = pool.apply_async(rsa_encrypt_text, args=(chunk, public_key, key_length, num_threads, False, encoding,))
                    cipher_list.append(cihper)
                Path(str(plain_file_path)+f".chunk.{i}").unlink()
            pool.close()
            pool.join()
        else:
            with open(plain_file_path, "rb") as f_chunk:
                chunk = f_chunk.read()
                cipher_list = rsa_encrypt_text(chunk, public_key, key_length, num_threads, False, encoding)
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


@SECRET.register_module()
def rsa_decrypt_file(crypto_file_path: PathLikeType,
                     plain_save_path: PathLikeType,
                     private_key: Union[bytes, PathLikeType],
                     key_length: int = 2048,
                     num_process: int = 1,
                     num_threads: int = 1,
                     encoding: str = "utf-8",
                     sentinel: Any = 0,
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
        sentinel (Any, optional): sentinel value for RSA decryption. Defaults to 0.
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
                    plain = pool.apply_async(rsa_decrypt_text, args=(chunk, private_key, key_length, num_threads, False, False, encoding, sentinel,))
                    plain_list.append(plain)
                Path(str(crypto_file_path)+f".chunk.{i}").unlink()
            pool.close()
            pool.join()
        else:
            with open(crypto_file_path, 'rb') as f_chunk:
                chunk = f_chunk.read()
                plain_list = [rsa_decrypt_text(chunk, private_key, key_length, num_threads, False, False, encoding, sentinel)]
        
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

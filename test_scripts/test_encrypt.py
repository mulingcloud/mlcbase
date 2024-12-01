import os
import random
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from Crypto.Cipher import AES
from mlcbase import *


@wrap_module_timer
def test_aes_encrypt_small_file(file_path, key, iv, mode, logger):
    logger.info("Encrypting small file...")
    size = get_file_size(file_path)
    logger.info(f"File size: {size[0]} {size[1]}")
    save_path = f"aes_encrypt_{mode}_{Path(file_path).name}.bin"
    if not aes_entrypt_file(file_path, save_path, key=key, iv=iv, mode=mode, logger=logger):
        raise RuntimeError("Failed to encrypt file using AES")


@wrap_module_timer
def test_aes_decrypt_small_file(ori_file_path, key, iv, mode, logger):
    logger.info("Decrypting small file...")
    ori_path = f"aes_encrypt_{mode}_{Path(ori_file_path).name}.bin"
    save_path = f"aes_decrypt_{mode}_{Path(ori_file_path).name}"
    if not aes_decrypt_file(ori_path, save_path, key=key, iv=iv, mode=mode, logger=logger):
        raise RuntimeError("Failed to decrypt file using AES")
    logger.info("checking file MD5...")
    ori_file_md5 = get_file_md5(ori_file_path)
    de_file_md5 = get_file_md5(save_path)
    if ori_file_md5 != de_file_md5:
        raise RuntimeError("Failed to decrypt file using AES")
    

@wrap_module_timer
def test_aes_encrypt_large_file(file_path, key, iv, mode, logger):
    logger.info("Encrypting large file...")
    size = get_file_size(file_path)
    logger.info(f"File size: {size[0]} {size[1]}")
    save_path = f"aes_encrypt_{mode}_{Path(file_path).name}.bin"
    if not aes_entrypt_file(file_path, save_path, key=key, iv=iv, mode=mode, logger=logger):
        raise RuntimeError("Failed to encrypt file using AES")


@wrap_module_timer
def test_aes_decrypt_large_file(ori_file_path, key, iv, mode, logger):
    logger.info("Decrypting large file...")
    ori_path = f"aes_encrypt_{mode}_{Path(ori_file_path).name}.bin"
    save_path = f"aes_decrypt_{mode}_{Path(ori_file_path).name}"
    if not aes_decrypt_file(ori_path, save_path, key=key, iv=iv, mode=mode, logger=logger):
        raise RuntimeError("Failed to decrypt file using AES")
    logger.info("checking file MD5...")
    ori_file_md5 = get_file_md5(ori_file_path)
    de_file_md5 = get_file_md5(save_path)
    if ori_file_md5 != de_file_md5:
        raise RuntimeError("Failed to decrypt file using AES")
    

@wrap_module_timer
def test_rsa_encrypt_small_file(file_path, key, key_length, logger):
    logger.info("Encrypting small file...")
    size = get_file_size(file_path)
    logger.info(f"File size: {size[0]} {size[1]}")
    save_path = f"rsa_small_encrypt_{Path(file_path).name}.bin"
    if not rsa_encrypt_file(file_path, save_path, public_key=key, key_length=key_length, logger=logger):
        raise RuntimeError("Failed to encrypt file using RSA")
    

@wrap_module_timer
def test_rsa_decrypt_small_file(ori_file_path, key, key_length, logger):
    logger.info("Decrypting small file...")
    ori_path = f"rsa_small_encrypt_{Path(ori_file_path).name}.bin"
    save_path = f"rsa_small_decrypt_{Path(ori_file_path).name}"
    if not rsa_decrypt_file(ori_path, save_path, private_key=key, key_length=key_length, logger=logger):
        raise RuntimeError("Failed to decrypt file using RSA")
    logger.info("checking file MD5...")
    ori_file_md5 = get_file_md5(ori_file_path)
    de_file_md5 = get_file_md5(save_path)
    if ori_file_md5 != de_file_md5:
        raise RuntimeError("Failed to decrypt file using RSA")


@wrap_module_timer
def test_rsa_encrypt_large_file(file_path, key, key_length, logger):
    logger.info("Encrypting large file...")
    size = get_file_size(file_path)
    logger.info(f"File size: {size[0]} {size[1]}")
    save_path = f"rsa_large_encrypt_{Path(file_path).name}.bin"
    if not rsa_encrypt_file(file_path, save_path, public_key=key, key_length=key_length, logger=logger):
        raise RuntimeError("Failed to encrypt file using RSA")
    

@wrap_module_timer
def test_rsa_decrypt_large_file(ori_file_path, key, key_length, logger):
    logger.info("Decrypting large file...")
    ori_path = f"rsa_large_encrypt_{Path(ori_file_path).name}.bin"
    save_path = f"rsa_large_decrypt_{Path(ori_file_path).name}"
    if not rsa_decrypt_file(ori_path, save_path, private_key=key, key_length=key_length, logger=logger):
        raise RuntimeError("Failed to decrypt file using RSA")
    logger.info("checking file MD5...")
    ori_file_md5 = get_file_md5(ori_file_path)
    de_file_md5 = get_file_md5(save_path)
    if ori_file_md5 != de_file_md5:
        raise RuntimeError("Failed to decrypt file using RSA")
    

@wrap_module_timer
def test_rsa_encrypt_large_file_accelerate(file_path, key, key_length, num_process, num_threads, logger):
    logger.info(f"Encrypting large file with accelerate (num_process={num_process}, num_threads={num_threads})...")
    size = get_file_size(file_path)
    logger.info(f"File size: {size[0]} {size[1]}")
    save_path = f"rsa_large_accelerated_encrypt_{Path(file_path).name}.bin"
    if not rsa_encrypt_file(
        file_path, save_path, public_key=key, key_length=key_length, num_process=num_process, num_threads=num_threads, logger=logger
    ):
        raise RuntimeError("Failed to encrypt file using RSA")
    

@wrap_module_timer
def test_rsa_decrypt_large_file_accelerate(ori_file_path, key, key_length, num_process, num_threads, logger):
    logger.info(f"Decrypting large file with accelerate (num_process={num_process}, num_threads={num_threads})...")
    ori_path = f"rsa_large_accelerated_encrypt_{Path(ori_file_path).name}.bin"
    save_path = f"rsa_large_accelerated_decrypt_{Path(ori_file_path).name}"
    if not rsa_decrypt_file(
        ori_path, save_path, private_key=key, key_length=key_length, num_process=num_process, num_threads=num_threads, logger=logger
    ):
        raise RuntimeError("Failed to decrypt file using RSA")
    logger.info("checking file MD5...")
    ori_file_md5 = get_file_md5(ori_file_path)
    de_file_md5 = get_file_md5(save_path)
    if ori_file_md5 != de_file_md5:
        raise RuntimeError("Failed to decrypt file using RSA")


def run():
    logger = Logger()
    logger.init_logger()
    start_time = datetime.now()

    ## encrypt password
    logger.info("Testing encrypt and verify password...")
    password = random.choices("0123456789abcdef", k=20)
    password = "".join(password)
    logger.info(f"Password: {password}")
    for method in ["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]:
        new_password = random.choices("0123456789abcdef", k=20)
        new_password = "".join(new_password)
        cipher = encrypt_password(password, method)
        if password == new_password:
            if not verify_password(new_password, cipher, method):
                raise RuntimeError(f"Failed to verify password with {method}")
        else:
            if verify_password(new_password, cipher, method):
                raise RuntimeError(f"Failed to verify password with {method}")
        if not verify_password(password, cipher, method):
            raise RuntimeError(f"Failed to verify password with {method}")
        logger.success(f"{method} passed")
    
    ## test materials
    plain_text = "Hello world! Welcome to use MuLingCloud. We aim to let everthing become easier."
    small_file_path = str(Path(__file__).parent.parent / "tutorial" / "examples" / "jsonfile.json")
    large_file_path = str(Path(__file__).parent.parent / "tutorial" / "examples" / "YOLOv9.pdf")

    ## aes
    logger.info("Testing AES (CBC mode)...")
    key = random_hex(16)
    iv = random_hex(16)
    logger.info("Encrypt and decrypt text using AES (CBC mode)...")
    cipher_text = aes_encrypt_text(plain_text, key=key, iv=iv, mode=AES.MODE_CBC)
    de_cipher = aes_decrypt_text(cipher_text, key=key, iv=iv, mode=AES.MODE_CBC)
    if de_cipher != plain_text:
        raise RuntimeError("Failed to decrypt text using AES (CBC mode)")
    logger.info("Encrypt and decrypt file using AES (CBC mode)...")
    small_file_path = str(Path(__file__).parent.parent / "tutorial" / "examples" / "jsonfile.json")
    large_file_path = str(Path(__file__).parent.parent / "tutorial" / "examples" / "YOLOv9.pdf")
    test_aes_encrypt_small_file(small_file_path, key, iv, AES.MODE_CBC, logger)
    test_aes_decrypt_small_file(small_file_path, key, iv, AES.MODE_CBC, logger)
    test_aes_encrypt_large_file(large_file_path, key, iv, AES.MODE_CBC, logger)
    test_aes_decrypt_large_file(large_file_path, key, iv, AES.MODE_CBC, logger)
    logger.success("AES (CBC mode) passed")

    logger.info("Testing AES (ECB mode)...")
    logger.info("Encrypt and decrypt text using AES (ECB mode)...")
    cipher_text = aes_encrypt_text(plain_text, key=key, iv=iv, mode=AES.MODE_ECB)
    de_cipher = aes_decrypt_text(cipher_text, key=key, iv=iv, mode=AES.MODE_ECB)
    if de_cipher != plain_text:
        raise RuntimeError("Failed to decrypt text using AES (ECB mode)")
    logger.info("Encrypt and decrypt file using AES (ECB mode)...")
    test_aes_encrypt_small_file(small_file_path, key, iv, AES.MODE_ECB, logger)
    test_aes_decrypt_small_file(small_file_path, key, iv, AES.MODE_ECB, logger)
    test_aes_encrypt_large_file(large_file_path, key, iv, AES.MODE_ECB, logger)
    test_aes_decrypt_large_file(large_file_path, key, iv, AES.MODE_ECB, logger)
    logger.success("AES (ECB mode) passed")

    remove(f"aes_encrypt_{AES.MODE_ECB}_{Path(small_file_path).name}.bin")
    remove(f"aes_encrypt_{AES.MODE_CBC}_{Path(small_file_path).name}.bin")
    remove(f"aes_encrypt_{AES.MODE_ECB}_{Path(large_file_path).name}.bin")
    remove(f"aes_encrypt_{AES.MODE_CBC}_{Path(large_file_path).name}.bin")
    remove(f"aes_decrypt_{AES.MODE_ECB}_{Path(small_file_path).name}")
    remove(f"aes_decrypt_{AES.MODE_CBC}_{Path(small_file_path).name}")
    remove(f"aes_decrypt_{AES.MODE_ECB}_{Path(large_file_path).name}")
    remove(f"aes_decrypt_{AES.MODE_CBC}_{Path(large_file_path).name}")

    ## rsa
    logger.info("Testing RSA...")
    key_length = 2048
    logger.info(f"Creating RSA keys (key_length={key_length})...")
    keys = create_rsa_keys(key_length=key_length, key_format="PKCS#8", return_keys=True)
    if keys is None:
        raise RuntimeError("Failed to create RSA keys")
    public_key, private_key = keys
    logger.info("Encrypt and decrypt text using RSA...")
    cipher_text = rsa_encrypt_text(plain_text, public_key=public_key, key_length=key_length)
    de_cipher = rsa_decrypt_text(cipher_text, private_key=private_key, key_length=key_length)
    if de_cipher != plain_text:
        raise RuntimeError("Failed to decrypt text using RSA")
    logger.info("Sign and verify text using RSA...")
    signature = rsa_sign_text(plain_text, private_key=private_key)
    if not rsa_verify_signature(plain_text, signature, public_key=public_key):
        raise RuntimeError("Failed to verify signature using RSA")
    logger.info("Encrypt and decrypt file using RSA...")
    test_rsa_encrypt_small_file(small_file_path, public_key, key_length, logger)
    test_rsa_decrypt_small_file(small_file_path, private_key, key_length, logger)
    test_rsa_encrypt_large_file(large_file_path, public_key, key_length, logger)
    test_rsa_decrypt_large_file(large_file_path, private_key, key_length, logger)
    num_process = os.cpu_count()
    if num_process > 8:
        num_process = 8
    if num_process > 1 and num_process % 2 != 0:
        num_process -= 1
    num_threads = 8
    logger.info(f"Testing RSA acceleration with {num_process} processes and {num_threads} threads...")
    test_rsa_encrypt_large_file_accelerate(large_file_path, public_key, key_length, num_process, num_threads, logger)
    test_rsa_decrypt_large_file_accelerate(large_file_path, private_key, key_length, num_process, num_threads, logger)
    logger.success("RSA passed")

    remove(f"rsa_small_encrypt_{Path(small_file_path).name}.bin")
    remove(f"rsa_small_decrypt_{Path(small_file_path).name}")
    remove(f"rsa_large_encrypt_{Path(large_file_path).name}.bin")
    remove(f"rsa_large_decrypt_{Path(large_file_path).name}")
    remove(f"rsa_large_accelerated_encrypt_{Path(large_file_path).name}.bin")
    remove(f"rsa_large_accelerated_decrypt_{Path(large_file_path).name}")

    end_time = datetime.now()
    runtime_analysis(start_time, end_time, "s")
    logger.info("All tests passed!")


if __name__ == '__main__':
    run()

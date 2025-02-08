import platform
import argparse
from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import *


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--python_version", required=True)

    args = parser.parse_args()
    return args


def parse_test_title(title: str, length: int = 80, padding: str = "="):
    assert len(title) <= length
    rest_length = length - len(title)
    left_padding = rest_length // 2 - 1
    right_padding = rest_length - left_padding - 1 
    return left_padding * padding + " " + title + " " + right_padding * padding


def run():
    args = parse_args()

    logger = Logger()
    logger.init_logger()

    py_version = "".join(args.python_version.split("."))
    sys_info = f"{platform.system().lower()}_{py_version}"

    ## KV v1
    mount_path = "test_kv1"
    path = f"{sys_info}_{random_hex(6, uppercase=False)}"
    logger.info(parse_test_title("Testing KV v1 engine..."))
    logger.info(parse_test_title("Accessing KV v1 secrets engine..."))
    kv1_engine = VaultSecretEngineKV1(
        url=args.host, 
        auth_cfg=dict(method="userpass", username=args.user, password=args.password),
        logger=logger
    )
    logger.info(parse_test_title("Testing create secret path..."))
    if not kv1_engine.create_secret_path(mount_path, path):
        raise RuntimeError("KV v1 create secret path failed")
    logger.info(parse_test_title("Testing read secret..."))
    if kv1_engine.read_secret(mount_path, path, "placeholder") is None:
        raise RuntimeError("KV v1 secret read failed")
    logger.info(parse_test_title("Testing add secret..."))
    added_secrets = {f"secret_{sys_info}": random_hex(6)}
    if not kv1_engine.add_secret(mount_path, path, added_secrets):
        raise RuntimeError("KV v1 secret add failed")
    logger.info(parse_test_title("Testing update secret..."))
    new_secret = random_hex(6)
    updated_secrets = {f"secret_{sys_info}": new_secret}
    kv1_engine.update_secret(mount_path, path, updated_secrets)
    if kv1_engine.read_secret(mount_path, path, f"secret_{sys_info}") != new_secret:
        raise RuntimeError("KV v1 secret update failed")
    logger.info(parse_test_title("Testing list secret..."))
    if kv1_engine.list_secret(mount_path, path) is None:
        raise RuntimeError("KV v1 secret list failed")
    logger.info(parse_test_title("Testing delete secret..."))
    if not kv1_engine.delete_secret(mount_path, path, f"secret_{sys_info}"):
        raise RuntimeError("KV v1 secret delete failed")
    logger.info("Testing delete secret path...")
    if not kv1_engine.delete_secret_path(mount_path, path):
        raise RuntimeError("KV v1 secret path delete failed")
    logger.success("Testing KV v1 engine... [OK]")

    ## KV v2
    mount_path = "test_kv2"
    path = f"{sys_info}_{random_hex(6, uppercase=False)}"
    logger.info(parse_test_title("Testing KV v2 engine..."))
    logger.info(parse_test_title("Accessing KV v2 secrets engine..."))
    kv2_engine = VaultSecretEngineKV2(
        url=args.host, 
        auth_cfg=dict(method="userpass", username=args.user, password=args.password),
        logger=logger
    )
    logger.info(parse_test_title("Testing create secret path..."))
    if not kv2_engine.create_secret_path(mount_path, path):
        raise RuntimeError("KV v2 create secret path failed")
    logger.info(parse_test_title("Testing read the configuration of the secret engine..."))
    engine_cfg = kv2_engine.read_engine_config(mount_path)
    if engine_cfg is None:
        raise RuntimeError("KV v2 read engine config failed")
    logger.info(f"Engine config: {engine_cfg}")
    logger.info(parse_test_title("Testing set the configuration of the secret engine..."))
    if not kv2_engine.set_engine_config(mount_path, dict(max_versions=5)):
        raise RuntimeError("KV v2 set engine config failed")
    new_engine_cfg = kv2_engine.read_engine_config(mount_path)
    logger.info(f"New engine config: {new_engine_cfg}")
    logger.info(parse_test_title("Testing add secret..."))
    if not kv2_engine.add_secret(mount_path, path, dict(new_secret="added_new_secret")):
        raise RuntimeError("KV v2 add secret failed")
    logger.info(parse_test_title("Testing read all secrets in the engine..."))
    secret = kv2_engine.read_secret(mount_path, path)
    if secret is None:
        raise RuntimeError("KV v2 read secret failed")
    logger.info(f"All secrets: {secret}")
    secret = kv2_engine.read_secret(mount_path, path, key="new_secret")
    logger.info(f"Secret (new_secret): {secret}")
    secret = kv2_engine.read_secret(mount_path, path, version=1)
    logger.info(f"Secret (version=1): {secret}")
    logger.info(parse_test_title("Testing read secret metadata..."))
    secret_meta = kv2_engine.read_secret_metadata(mount_path, path)
    if secret_meta is None:
        raise RuntimeError("KV v2 read secret metadata failed")
    logger.info(f"Secret metadata: {secret_meta}")
    logger.info(parse_test_title("Testing get all secret versions..."))
    secret_versions = kv2_engine.get_all_secret_versions(mount_path, path)
    if secret_versions is None:
        raise RuntimeError("KV v2 get all secret versions failed")
    logger.info(f"Secret versions: {secret_versions}")
    logger.info(parse_test_title("Testing update secret..."))
    if not kv2_engine.update_secret(mount_path, path, dict(new_secret="updated_new_secret")):
        raise RuntimeError("KV v2 update secret failed")
    secret = kv2_engine.read_secret(mount_path, path, key="new_secret")
    logger.info(f"Updated secret (new_secret): {secret}")
    logger.info(parse_test_title("Testing read secret subkeys..."))
    kv2_engine.add_secret(
        mount_path, 
        path, 
        dict(new_secret_root=dict(sub_key_1="value1", sub_key_2="value2", sub_key_3=dict(subsub_key1="value3", subsub_key2="value4")))
    )
    secret = kv2_engine.read_secret_subkeys(mount_path, path)
    logger.info(f"Secret subkeys: {secret}")
    secret = kv2_engine.read_secret_subkeys(mount_path, path, depth=1)
    logger.info(f"Secret subkeys (depth=1): {secret}")
    secret = kv2_engine.read_secret_subkeys(mount_path, path, depth=2)
    logger.info(f"Secret subkeys (depth=2): {secret}")
    secret = kv2_engine.read_secret_subkeys(mount_path, path, depth=3)
    logger.info(f"Secret subkeys (depth=3): {secret}")
    logger.info(parse_test_title("Testing delete secret..."))
    logger.info(f"Latest version of secret: {kv2_engine.read_secret(mount_path, path)}")
    logger.info("Deleting the latest version")
    if not kv2_engine.delete_secret(mount_path, path):
        raise RuntimeError("KV v2 secret delete failed")
    logger.info(f"Latest version of secret: {kv2_engine.read_secret(mount_path, path)}")
    logger.info(parse_test_title("Testing undelete secret..."))
    if not kv2_engine.undelete_secret(mount_path, path, version=4):
        raise RuntimeError("KV v2 secret undelete failed")
    logger.info(f"Latest version of secret: {kv2_engine.read_secret(mount_path, path)}")
    logger.info(parse_test_title("Testing destroy secret (cannot be recovered)..."))
    if not kv2_engine.destroy_secret(mount_path, path, version=4):
        raise RuntimeError("KV v2 secret destroy failed")
    logger.info(f"Latest version of secret: {kv2_engine.read_secret(mount_path, path)}")
    logger.info(parse_test_title("Testing list secret..."))
    secrets = kv2_engine.list_secret(mount_path, path)
    if secrets is None:
        raise RuntimeError("KV v2 secret list failed")
    logger.info(f"List secrets: {secrets}")
    logger.info(parse_test_title("Testing delete secret path..."))
    if not kv2_engine.delete_secret_path(mount_path, path):
        raise RuntimeError("KV v2 secret path delete failed")
    logger.success("Testing KV v2 engine... [OK]")

    ## Cubbyhole
    path = f"{sys_info}__{random_hex(6, uppercase=False)}"
    logger.info(parse_test_title("Testing Cubbyhole engine..."))
    logger.info(parse_test_title("Accessing Cubbyhole secrets engine..."))
    cubbyhole = VaultSecretEngineCubbyhole(
        url=args.host, 
        auth_cfg=dict(method="userpass", username=args.user, password=args.password),
        logger=logger
    )
    logger.info(parse_test_title("Testing create secret path..."))
    if not cubbyhole.create_secret_path(path):
        raise RuntimeError("Cubbyhole create secret path failed")
    logger.info(parse_test_title("Testing read secret..."))
    secret = cubbyhole.read_secret(path)
    if secret is None:
        raise RuntimeError("Cubbyhole read secret failed")
    logger.info(f"Secret: {secret}")
    logger.info(f"Secret (placeholder): {cubbyhole.read_secret(path, key='placeholder')}")
    logger.info(parse_test_title("Testing list secret..."))
    secrets = cubbyhole.list_secret(path)
    if secrets is None:
        raise RuntimeError("Cubbyhole list secret failed")
    logger.info(f"List secrets: {secrets}")
    logger.info(parse_test_title("Testing add secret..."))
    if not cubbyhole.add_secret(path, dict(new_secret_1="value1", new_secret_2="value2")):
        raise RuntimeError("Cubbyhole add secret failed")
    logger.info(f"Current secrets: {cubbyhole.list_secret(path)}")
    logger.info(parse_test_title("Testing update secret..."))
    if not cubbyhole.update_secret(path, dict(new_secret_1="value1_updated")):
        raise RuntimeError("Cubbyhole update secret failed")
    logger.info(f"Current secrets: {cubbyhole.list_secret(path)}")
    logger.info(parse_test_title("Testing delete secret..."))
    if not cubbyhole.delete_secret(path, key="placeholder"):
        raise RuntimeError("Cubbyhole delete secret failed")
    logger.info(f"Current secrets: {cubbyhole.list_secret(path)}")
    logger.info(parse_test_title("Testing delete secret path..."))
    if not cubbyhole.delete_secret_path(path):
        raise RuntimeError("Cubbyhole delete secret path failed")
    logger.success("Testing Cubbyhole engine... [OK]")

    ## TOTP
    mount_path = "test_totp"
    name = f"{sys_info}__{random_hex(6, uppercase=False)}"
    logger.info(parse_test_title("Testing TOTP engine..."))
    logger.info(parse_test_title("Accessing TOTP secrets engine..."))
    totp_engine = VaultSecretEngineTOTP(
        url=args.host, 
        auth_cfg=dict(method="userpass", username=args.user, password=args.password),
        logger=logger
    )
    logger.info(parse_test_title("Testing create key..."))
    key_info = totp_engine.create_key(mount_path,
                                      name=name,
                                      account_name="your_account_name",
                                      return_secret=True,
                                      return_qr_code=False)
    if key_info is None:
        raise RuntimeError("TOTP create key failed")
    logger.info(f"Key info: {key_info}")
    logger.info(parse_test_title("Testing read key..."))
    key_info = totp_engine.read_key(mount_path, name)
    if key_info is None:
        raise RuntimeError("TOTP read key failed")
    logger.info(f"Read key: {key_info}")
    logger.info(parse_test_title("Testing update key..."))
    key = totp_engine.update_key(mount_path, 
                                 name, 
                                 account_name="your_new_account_name", 
                                 algorithm="SHA256", 
                                 return_secret_key=True)
    if not is_str(key):
        raise RuntimeError("TOTP update key failed")
    logger.info(f"Current key: {totp_engine.read_key(mount_path, name)}")
    logger.info(parse_test_title("Testing list key..."))
    keys = totp_engine.list_key(mount_path)
    if keys is None:
        raise RuntimeError("TOTP list key failed")
    logger.info(f"List keys: {keys}")
    logger.info(parse_test_title("Testing generate code..."))
    code = totp_engine.generate_code(mount_path, name)
    if code is None:
        raise RuntimeError("TOTP generate code failed")
    logger.info(f"Generated code: {code}")
    logger.info(parse_test_title("Testing validate code..."))
    result = totp_engine.validate_code(mount_path, name, code)
    if result is None:
        raise RuntimeError("TOTP validate code failed")
    logger.info(f"Validate code: {result}")
    logger.info(parse_test_title("Testing delete key..."))
    if not totp_engine.delete_key(mount_path, name):
        raise RuntimeError("TOTP delete key failed")
    logger.success("Testing TOTP engine... [OK]")

    ## TODO: Transit
    # mount_path = "test_transit"
    # logger.info(parse_test_title("Testing Transit engine..."))
    # logger.info(parse_test_title("Accessing Transit secrets engine..."))
    # transit = VaultSecretEngineTransit(
    #     url=args.host, 
    #     auth_cfg=dict(method="userpass", username=args.user, password=args.password),
    #     logger=logger
    # )
    # logger.info(parse_test_title("Testing create key..."))
    # logger.info("Creating aes key...")
    # status = transit.create_key(mount_path, name=f"test_aes_divergent_{sys_info}")
    # if not status:
    #     raise RuntimeError("Transit create key failed")
    # status = transit.create_key(mount_path, name=f"test_aes_convergent_{sys_info}", convergent_encryption=True, derived=True)
    # logger.info("Creating chacha key...")
    # transit.create_key(mount_path, name=f"test_chacha20_{sys_info}", key_type="chacha20-poly1305")
    # logger.info("Creating ed25519 key...")
    # transit.create_key(mount_path, name=f"test_ed25519_{sys_info}", key_type="ed25519")
    # logger.info("Creating ecdsa key...")
    # transit.create_key(mount_path, name=f"test_ecdsa_{sys_info}", key_type="ecdsa-p256")
    # logger.info("Creating rsa key...")
    # transit.create_key(mount_path, name=f"test_rsa_{sys_info}", key_type="rsa-2048")
    # logger.info("Creating hmac key...")
    # transit.create_key(mount_path, name=f"test_hmac_{sys_info}", key_type="hmac", key_size=40)

    # # TODO: import key
    # # logger.info(parse_test_title("Testing import key..."))
    # # logger.info("1. Private/Symmetric Key importing (take chacha20 as an example)...")
    # # target_key = random_hex(32, seed=random.randint(0, 2**32-1))
    # # status = transit.import_key(mount_path, 
    # #                             name="test_import_private", 
    # #                             private_or_symmetric_key=target_key,
    # #                             key_type="chacha20-poly1305")
    # # if not status:
    # #     raise RuntimeError("Transit import private/symmetric key failed")
    # # logger.info("2. Public Key-only importing...")

    # logger.info(parse_test_title("Testing update key config..."))
    # if not transit.update_key_config(mount_path, name=f"test_aes_divergent_{sys_info}", deletion_allowed=True):
    #     raise RuntimeError("Transit update key config failed")
    # transit.update_key_config(mount_path, name=f"test_aes_convergent_{sys_info}", deletion_allowed=True)
    # transit.update_key_config(mount_path, name=f"test_chacha20_{sys_info}", deletion_allowed=True)
    # transit.update_key_config(mount_path, name=f"test_ed25519_{sys_info}", deletion_allowed=True)
    # transit.update_key_config(mount_path, name=f"test_ecdsa_{sys_info}", deletion_allowed=True)
    # transit.update_key_config(mount_path, name=f"test_rsa_{sys_info}", deletion_allowed=True)
    # transit.update_key_config(mount_path, name=f"test_hmac_{sys_info}", deletion_allowed=True)
    # # transit.update_key_config(mount_path, name="test_import_private", deletion_allowed=True)
    # # TODO
    # logger.info(parse_test_title("Testing delete key..."))
    # if not transit.delete_key(mount_path, name=f"test_aes_divergent_{sys_info}"):
    #     raise RuntimeError("Transit delete key failed")
    # transit.delete_key(mount_path, name=f"test_aes_convergent_{sys_info}")
    # transit.delete_key(mount_path, name=f"test_chacha20_{sys_info}")
    # transit.delete_key(mount_path, name=f"test_ed25519_{sys_info}")
    # transit.delete_key(mount_path, name=f"test_ecdsa_{sys_info}")
    # transit.delete_key(mount_path, name=f"test_rsa_{sys_info}")
    # transit.delete_key(mount_path, name=f"test_hmac_{sys_info}")
    # # transit.delete_key(mount_path, name="test_import_private")
    # logger.success("Testing Transit engine... [OK]")


if __name__ == "__main__":
    run()

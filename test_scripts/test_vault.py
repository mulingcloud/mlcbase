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


def run():
    args = parse_args()

    logger = Logger()
    logger.init_logger()

    py_version = "".join(args.python_version.split("."))
    sys_info = f"{platform.system()}_{py_version}"

    ## KV v1
    mount_path = "test_kv1"
    path = f"test_path_{sys_info}"
    logger.info("Testing KV v1 engine...")
    logger.info("Accessing KV v1 secrets engine...")
    kv1_engine = VaultSecretEngineKV1(
        url=args.host, 
        auth_cfg=dict(method="userpass", username=args.user, password=args.password),
        logger=logger
    )
    logger.info("Testing create secret path...")
    if not kv1_engine.create_secret_path(mount_path, path):
        raise RuntimeError("KV v1 create secret path failed")
    logger.info("Testing read secret...")
    if kv1_engine.read_secret(mount_path, path, "placeholder") is None:
        raise RuntimeError("KV v1 secret read failed")
    logger.info("Testing add secret...")
    added_secrets = {f"secret_{sys_info}": random_hex(6)}
    if not kv1_engine.add_secret(mount_path, path, added_secrets):
        raise RuntimeError("KV v1 secret add failed")
    logger.info("Testing update secret...")
    new_secret = random_hex(6)
    updated_secrets = {f"secret_{sys_info}": new_secret}
    kv1_engine.update_secret(mount_path, path, updated_secrets)
    if kv1_engine.read_secret(mount_path, path, f"secret_{sys_info}") != new_secret:
        raise RuntimeError("KV v1 secret update failed")
    logger.info("Testing list secret...")
    if kv1_engine.list_secret(mount_path, path) is None:
        raise RuntimeError("KV v1 secret list failed")
    logger.info("Testing delete secret...")
    if not kv1_engine.delete_secret(mount_path, path, f"secret_{sys_info}"):
        raise RuntimeError("KV v1 secret delete failed")
    logger.info("Testing delete secret path...")
    if not kv1_engine.delete_secret_path(mount_path, path):
        raise RuntimeError("KV v1 secret path delete failed")
    logger.success("Testing KV v1 engine... [OK]")

    ## TODO: KV v2
    mount_path = "test_kv2"
    path = f"test_path_{sys_info}"
    logger.info("Testing KV v2 engine...")
    logger.info("Accessing KV v2 secrets engine...")
    kv2_engine = VaultSecretEngineKV2(
        url=args.host, 
        auth_cfg=dict(method="userpass", username=args.user, password=args.password),
        logger=logger
    )
    logger.info("Testing create secret path...")
    if not kv2_engine.create_secret_path(mount_path, path):
        raise RuntimeError("KV v2 create secret path failed")
    
    logger.info("Testing list secret...")
    if kv2_engine.list_secret(mount_path, path) is None:
        raise RuntimeError("KV v2 secret list failed")
    logger.info("Testing delete secret path...")
    if not kv2_engine.delete_secret_path(mount_path, path):
        raise RuntimeError("KV v2 secret path delete failed")
    # logger.success("Testing KV v2 engine... [OK]")

    ## TODO: TOTP
    # logger.info("Testing TOTP engine...")
    # logger.success("Testing TOTP engine... [OK]")

    ## TODO: Transit
    # logger.info("Testing Transit engine...")
    # logger.success("Testing Transit engine... [OK]")


if __name__ == "__main__":
    run()

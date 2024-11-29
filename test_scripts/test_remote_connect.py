import os
import shutil
import argparse
from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import *


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--root_path", required=True)
    parser.add_argument("--python_version", required=True)

    args = parser.parse_args()
    return args


def run():
    args = parse_args()

    logger = Logger()
    logger.init_logger()

    py_version = "".join(args.python_version.split("."))

    ## SSH
    logger.info("Testing SSH...")
    ssh_api = SSH(host=args.host,
                  port=int(args.port),
                  user=args.user,
                  password=args.password,
                  logger=logger)
    stdout, stderr = ssh_api.execute("ls")
    if stdout:
        logger.info(stdout)
    if stderr:
        logger.error(stderr)
    ssh_api.close()

    ## SFTP
    # prepare files
    local_file_path = str(ROOT/"tutorial"/"examples"/"jsonfile.json")
    remote_file_path = args.root_path + f"/jsonfile_{py_version}.json"
    local_dir_path = str(ROOT/"tutorial"/"examples"/"example_dir")
    remote_dir_path = args.root_path + f"/example_dir_{py_version}"
    remote_mkdir_path = args.root_path + f"/test_mkdir_{py_version}"
    local_recursive_dir_path = f"example_recursive_dir_{py_version}"
    create(local_recursive_dir_path)
    shutil.copyfile(local_file_path, os.path.join(local_recursive_dir_path, "jsonfile.json"))
    shutil.copytree(local_dir_path, os.path.join(local_recursive_dir_path, "example_dir"))
    remote_recursive_dir_path = args.root_path + f"/example_recursive_dir_{py_version}"

    logger.info("Testing SFTP...")
    sftp_api = SFTP(host=args.host,
                    port=int(args.port),
                    user=args.user,
                    password=args.password,
                    logger=logger)
    logger.info("Testing upload file...")
    if not sftp_api.upload_file(local_file_path, remote_file_path, "linux"):
        raise RuntimeError("upload file failed")
    logger.info("Testing download file...")
    if not sftp_api.download_file(remote_file_path, f"localfile_{py_version}.json", "linux"):
        raise RuntimeError("download file failed")
    if get_file_md5(local_file_path) != get_file_md5(f"localfile_{py_version}.json"):
        raise RuntimeError("downloaded file md5 is not equal to the original file")
    logger.info("Testing upload directory...")
    if not sftp_api.upload_dir(local_dir_path, remote_dir_path, "linux"):
        raise RuntimeError("upload directory failed")
    logger.info("Testing download directory...")
    if not sftp_api.download_dir(remote_dir_path, f"example_dir_{py_version}", "linux"):
        raise RuntimeError("download directory failed")
    logger.info("Testing remote existence checking...")
    if not sftp_api.remote_exists(remote_file_path, "linux"):
        raise RuntimeError("remote file existence checking failed")
    logger.info("Testing remote_is_file()...")
    if not sftp_api.remote_is_file(remote_file_path, "linux"):
        raise RuntimeError("remote_is_file() failed")
    logger.info("Testing remote_is_dir()...")
    if not sftp_api.remote_is_dir(remote_dir_path, "linux"):
        raise RuntimeError("remote_is_dir() failed")
    logger.info("Testing remote_mkdir()...")
    if not sftp_api.remote_mkdir(remote_mkdir_path, "linux"):
        raise RuntimeError("remote_mkdir() failed")
    logger.info("Testing remote_listdir()...")
    result = sftp_api.remote_listdir(remote_dir_path, "linux")
    if result is None:
        raise RuntimeError("remote_listdir() failed")
    else:
        [print(x) for x in result]
    logger.info("Testing remote remove file...")
    if not sftp_api.remote_remove(remote_file_path, "linux"):
        raise RuntimeError("remote_remove() failed")
    logger.info("Testing remote remove empty directory...")
    if not sftp_api.remote_remove(remote_mkdir_path, "linux"):
        raise RuntimeError("remote_remove() failed")
    sftp_api.upload_dir(local_recursive_dir_path, remote_recursive_dir_path, "linux")
    logger.info("Testing remote recursive remove directory...")
    if not sftp_api.remote_remove(remote_recursive_dir_path, "linux"):
        raise RuntimeError("remote_remove() failed")
    if sftp_api.remote_exists(remote_recursive_dir_path, "linux"):
        raise RuntimeError("remote_recursive_dir_path still exists")
    sftp_api.remote_remove(remote_dir_path, "linux")
    sftp_api.close()

    remove(f"localfile_{py_version}.json")
    remove(f"example_dir_{py_version}")
    remove(local_recursive_dir_path)
    logger.info("All tests passed!")


if __name__ == "__main__":
    run()

from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import *


def run():
    logger = Logger()
    logger.init_logger()

    ## create
    logger.info("Testing create...")
    if not create(str(ROOT/"testdir"), logger=logger):
        raise RuntimeError("Failed to create a directory")
    if not create(str(ROOT/"testdir/testfile.txt"), logger=logger):
        raise RuntimeError("Failed to create a file")
    
    ## remove
    logger.info("Testing remove...")
    if not remove(str(ROOT/"testdir/testfile.txt"), logger=logger):
        raise RuntimeError("Failed to remove a file")
    if not remove(str(ROOT/"testdir"), logger=logger):
        raise RuntimeError("Failed to remove a directory")
    
    ## listdir
    logger.info("Testing list directory...")
    result = listdir(str(ROOT/"tutorial"), logger=logger)
    if result is not None:
        for i in result:
            print(i)
    else:
        raise RuntimeError("Failed to list directory")
    logger.info("Testing list directory sorting with suffix...")
    result = listdir(str(ROOT/"tutorial"), sort_func=lambda x: x.suffix, logger=logger)
    if result is not None:
        for i in result:
            print(i)
    else:
        raise RuntimeError("Failed to list directory")
    logger.info("Testing list directory sorting with suffix (reversed)...")
    result = listdir(str(ROOT/"tutorial"), sort_func=lambda x: x.suffix, reverse=True, logger=logger)
    if result is not None:
        for i in result:
            print(i)
    else:
        raise RuntimeError("Failed to list directory")
    
    ## get file size
    logger.info("Testing get file size...")
    file_Path = ROOT/"tutorial"/"examples"/"YOLOv9.pdf"
    logger.info("getting file size with auto unit...")
    size = get_file_size(str(file_Path))
    logger.info(f"{file_Path.name}: {size[0]} {size[1]}")
    logger.info("getting file size without auto unit...")
    size = get_file_size(str(file_Path), auto_unit=False)
    logger.info(f"{file_Path.name}: {size[0]} {size[1]}")
    logger.info("getting file size with specific unit...")
    size = get_file_size(str(file_Path), return_unit="KB")
    logger.info(f"{file_Path.name}: {size[0]} {size[1]}")
    logger.info("getting file size without truncate decimal...")
    size = get_file_size(str(file_Path), truncate_place=None)
    logger.info(f"{file_Path.name}: {size[0]} {size[1]}")

    ## get directory size
    logger.info("Testing get directory size...")
    dir_path = ROOT / "tutorial"
    size = get_dir_size(str(dir_path))
    logger.info(f"{dir_path.name}: {size[0]} {size[1]}")

    ## get meta information
    logger.info("Testing get meta information...")
    logger.info("getting meta information from a file")
    info = get_meta_info(str(file_Path))
    for k, v in info.items():
        logger.info(f"{file_Path.name} {k}: {v}")
    logger.info("getting meta information from a directory")
    info = get_meta_info(str(dir_path))
    for k, v in info.items():
        logger.info(f"{dir_path.name} {k}: {v}")

    ## get file md5
    logger.info("Testing get file md5...")
    md5 = get_file_md5(str(file_Path))
    logger.info(f"{file_Path.name} md5: {md5}")
    
    logger.success("All tests passed!")
    


if __name__ == "__main__":
    run()

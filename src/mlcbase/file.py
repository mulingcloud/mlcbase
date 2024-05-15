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
MuLingCloud base module: file operation

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import os
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Union

from .conifg import ConfigDict
from .logger import Logger
from .register import FILEOPT
from .misc import is_str, is_int

PathLikeType = Union[str, Path]

__all__ = ["create", "remove", "listdir", "get_file_size", "get_dir_size", "get_meta_info"]


@FILEOPT.register_module()
def create(path: PathLikeType,
           ftype: str = "auto",
           src: Optional[PathLikeType] = None,
           exist_ok: bool = True,
           overwrite: bool = False,
           logger: Optional[Logger] = None,
           **kwargs):
    """create a file, a directory or a symbolic link

    Args:
        path (PathLikeType)
        ftype (str, optional): options including "auto", "file", "dir", "symlink". Defaults to "auto" 
                               that determine the file type automactically.
        src (Optional[PathLikeType], optional): the source of a symbolic link. Defaults to None.
        exist_ok (bool, optional): if True, skip creating if the file already exists. Defaults to True.
        overwrite (bool, optional): if True, delete the existing one and create a new one. Only take 
                                    effect when path exists. Defaults to False.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if success, otherwise return False
    """
    assert ftype in ["auto", "file", "dir", "symlink"], "ftype should be: auto, file, dir, symlink"
    path = str(path)
    src = str(src) if src is not None else None

    if os.path.lexists(path):
        path_exist = True
        if overwrite:
            if logger is not None:
                logger.info(f'{path} already exists, but you try to overwrite it manually...')
            if not remove(path, logger):
                return False
            path_exist = False
        else:
            if exist_ok:
                if logger is not None:
                    logger.info(f'{path} already exists, skip creating')
                return True
    else:
        path_exist = False
    
    if ftype == "auto":
        if path_exist:
            if os.path.isfile(path):
                ftype = "file"
            elif os.path.isdir(path):
                ftype = "dir"
            elif os.path.islink(path):
                ftype = "symlink"
            else:
                if logger is not None:
                    logger.warning(f'[AUTO] unknown file type: {path}, try to create as a file...')
                ftype = "file"
        else:
            if src is None:
                suffix = os.path.splitext(path)[1]
                if suffix == "":
                    if logger is not None:
                        logger.info(f'[AUTO] create directory: {path}')
                    ftype = "dir"
                else:
                    if logger is not None:
                        logger.info(f'[AUTO] create file: {path}')
                    ftype = "file"
            else:
                # if src is provided, it will create a symbolic link
                if logger is not None:
                    logger.info(f'[AUTO] create symbolic link: {src} -> {path}')
                ftype = "symlink"

    if ftype == "file":
        try:
            f = open(path, 'w')
            f.close()
            return True
        except OSError as e:
            if logger is not None:
                logger.error(f'create file error: {str(e)}')
            return False

    if ftype == "dir":
        try:
            os.makedirs(path)
            return True
        except OSError as e:
            if logger is not None:
                logger.error(f'create directory error: {str(e)}')
            return False

    if ftype == "symlink":
        assert src is not None, "'src' is required when creating symbolic link"
        assert os.path.exists(src), f'The source of the symbolic link not exists: {src}'

        try:
            os.symlink(src, path, target_is_directory=kwargs.get("target_is_directory", False))
            return True
        except OSError as e:
            if logger is not None:
                logger.error(f'create symbolic link error: {str(e)}')
            return False
        

@FILEOPT.register_module()
def remove(path: PathLikeType, logger: Optional[Logger] = None):
    path = str(path)
    assert os.path.lexists(path), f'{path} is not exist'
    
    try:
        is_remove = False

        if os.path.isdir(path):
            shutil.rmtree(path)
            is_remove = True

        if os.path.isfile(path):
            os.remove(path)
            is_remove = True

        if os.path.islink(path):
            os.unlink(path)
            is_remove = True

        if not is_remove:
            if logger is not None:
                logger.error(f"remove error: unknown file type: {path}")
        return is_remove
    except OSError as e:
        if logger is not None:
            logger.error(f'remove error: {str(e)}')
        return False


@FILEOPT.register_module()
def listdir(path: PathLikeType, 
            sort_func: Optional[callable] = None,
            reverse: bool = False,
            return_path: bool = True,
            logger: Optional[Logger] = None):
    """list directory

    Args:
        path (PathLikeType)
        sort_func (Optional[callable], optional): sort function. Defaults to None.
        reverse (bool, optional): if reverse sort result. Defaults to False.
        return_path (bool, optional): return path or filename. Defaults to True.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        List[str]: return path if return_path is True, otherwise return filename.
        None: return None if error occurs.
    """
    try:
        generator = Path(path).absolute().iterdir()
        generator = sorted(generator, key=sort_func, reverse=reverse)
        if return_path:
            return [str(p) for p in generator]
        else:
            return [str(p.name) for p in generator]
    except OSError as e:
        if logger is not None:
            logger.error(f'list directory error: {str(e)}')
        return None


@FILEOPT.register_module()
def get_file_size(path: PathLikeType, 
                  return_unit: Optional[str] = None,
                  auto_unit: bool = True,
                  truncate_place: Optional[int] = 2):
    """get the size of file

    Args:
        path (PathLikeType)
        return_unit (Optional[str], optional): return a specific unit. Defaults to None.
        auto_unit (bool, optional): auto select unit. Defaults to True.
        truncate_place (int, optional): truncated decimal places, if None do not use the 
                                        truncation operation. Defaults to 2.

    Returns:
        tuple: (size, unit)
    """
    units = ['B', 'KB', 'MB', 'GB', 'TB']

    assert os.path.lexists(path), f'{path} not exist'
    assert os.path.isfile(path), f'{path} is not a file'
    assert return_unit is None or (is_str(return_unit) and return_unit.upper() in units), \
            f'return_unit should be: B, KB, MB, GB, TB. (lower case is also ok)'
    assert truncate_place is None or (is_int(truncate_place) and truncate_place >= 0), \
        f'truncate_place should be None or a positive integer'

    size = Path(path).stat().st_size

    if return_unit:
        unit = return_unit.upper()
        index = units.index(unit)

        precise_size = size / (1024 ** index)
        if truncate_place is not None:
            truncated_size = int(precise_size * (10 ** truncate_place)) / (10 ** truncate_place)
            return (truncated_size, unit)
        else:
            return (precise_size, unit)
    
    if auto_unit:
        last_size = None
        last_unit = None
        for index in range(len(units)):
            try_size = size / (1024 ** index)

            if try_size < 1:
                break

            last_size = try_size
            last_unit = units[index]

        precise_size = last_size
        unit = last_unit
        if truncate_place is not None:
            truncated_size = int(precise_size * (10 ** truncate_place)) / (10 ** truncate_place)
            return (truncated_size, unit)
        else:
            return (precise_size, unit)
    
    return (size, 'B')


@FILEOPT.register_module()
def get_dir_size(path: PathLikeType,
                 return_unit: Optional[str] = None,
                 auto_unit: bool = True,
                 truncate_place: Optional[int] = 2):
    """get the size of directory

    Args:
        path (PathLikeType)
        return_unit (Optional[str], optional): return specific unit. Defaults to None.
        auto_unit (bool, optional): auto select unit. Defaults to True.
        truncate_place (int, optional): truncated decimal places, if None do not use the 
                                        truncation operation. Defaults to 2.

    Returns:
        tuple: (size, unit)
    """
    units = ['B', 'KB', 'MB', 'GB', 'TB']

    assert os.path.lexists(path), f'{path} not exist'
    assert os.path.isdir(path), f'{path} is not a directory'
    assert return_unit is None or (is_str(return_unit) and return_unit.upper() in units), \
            f'return_unit should be: B, KB, MB, GB, TB. (lower case is also ok)'
    assert truncate_place is None or (is_int(truncate_place) and truncate_place >= 0), \
        f'truncate_place should be None or a positive integer'
    
    total_size = 0

    for p in listdir(path):
        if os.path.isfile(p):
            total_size += Path(p).stat().st_size
        if os.path.isdir(p):
            total_size += get_dir_size(p, return_unit="B")[0]

    if return_unit:
        unit = return_unit.upper()
        index = units.index(unit)
        
        precise_size = total_size / (1024 ** index)
        if truncate_place is not None:
            truncated_size = int(precise_size * (10 ** truncate_place)) / (10 ** truncate_place)
            return (truncated_size, unit)
        else:
            return (precise_size, unit)
    
    if auto_unit:
        last_size = None
        last_unit = None
        for index in range(len(units)):
            try_size = total_size / (1024 ** index)

            if try_size < 1:
                break

            last_size = try_size
            last_unit = units[index]

        precise_size = last_size
        unit = last_unit
        if truncate_place is not None:
            truncated_size = int(precise_size * (10 ** truncate_place)) / (10 ** truncate_place)
            return (truncated_size, unit)
        else:
            return (precise_size, unit)
    
    return (total_size, 'B')
    

@FILEOPT.register_module()
def get_meta_info(path: PathLikeType):
    """get the meta information of file or directory

    Args:
        path (PathLikeType)

    Meta information includes: path, directory, filename, suffix, size, create time, 
                               last access time, and last modify time.

    Returns:
        ConfigDict: meta information
    """
    assert os.path.lexists(path), f'{path} not exist'
    path = Path(path).absolute()

    meta_info = ConfigDict()
    meta_info.path = str(path)
    meta_info.directory = str(path.parent)
    meta_info.filename = path.name
    meta_info.suffix = path.suffix
    if path.is_file():
        meta_info.type = "file"
        size = get_file_size(path)
        meta_info.size = f"{size[0]} {size[1]}"
    if path.is_dir():
        meta_info.type = "directory"
        size = get_dir_size(path)
        meta_info.size = f"{size[0]} {size[1]}"
    if path.is_symlink():
        meta_info.type = "symbolic link"
        meta_info.source = os.readlink(path)
    meta_info.create_time = datetime.fromtimestamp(path.lstat().st_ctime).strftime('%Y-%m-%d %H:%M:%S')
    meta_info.last_access_time = datetime.fromtimestamp(path.lstat().st_atime).strftime('%Y-%m-%d %H:%M:%S')
    meta_info.last_modify_time = datetime.fromtimestamp(path.lstat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')

    return meta_info

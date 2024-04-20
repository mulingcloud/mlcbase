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
from pathlib import Path
from datetime import datetime
from typing import Optional, Union

from .conifg import ConfigDict
from .logger import Logger
from .misc import is_str, is_int

PathLikeType = Union[str, Path]


def mkdir(path: PathLikeType, 
          parents: bool = True, 
          exist_ok: bool = True, 
          logger: Optional[Logger] = None):
    """make directory

    Args:
        path (PathLikeType)
        parents (bool, optional): make parents if parents are not exist. 
                                  Defaults to True.
        exist_ok (bool, optional): if set True, when the path exists will 
                                  not raise error. Defaults to True.

    Returns:
        bool: return True if success, otherwise return False
    """
    try:
        Path(path).mkdir(parents=parents, exist_ok=exist_ok)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'make directory error: {str(e)}')
        return False


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


def get_file_size(path: PathLikeType, 
                  return_unit: Optional[str] = None,
                  auto_unit: bool = True,
                  truncate_place: Optional[int] = 2):
    """get the size of file

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

    assert Path(path).exists(), f'{path} not exist'
    assert Path(path).is_file(), f'{path} is not a file'
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

    assert Path(path).exists(), f'{path} not exist'
    assert Path(path).is_dir(), f'{path} is not a directory'
    assert return_unit is None or (is_str(return_unit) and return_unit.upper() in units), \
            f'return_unit should be: B, KB, MB, GB, TB. (lower case is also ok)'
    assert truncate_place is None or (is_int(truncate_place) and truncate_place >= 0), \
        f'truncate_place should be None or a positive integer'
    
    total_size = 0

    for p in listdir(path):
        if Path(p).is_file():
            total_size += Path(p).stat().st_size
        if Path(p).is_dir():
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
    

def get_meta_info(path: PathLikeType):
    """get the meta information of file or directory

    Args:
        path (PathLikeType)

    Meta information includes: path, directory, filename, suffix, size, create time, 
                               last access time, and last modify time.

    Returns:
        ConfigDict: meta information
    """
    assert Path(path).exists(), f'{path} not exist'
    # assert Path(path).is_file(), f'{path} is not a file'
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
    else:
        meta_info.type = "directory"
        size = get_dir_size(path)
        meta_info.size = f"{size[0]} {size[1]}"
    meta_info.create_time = datetime.fromtimestamp(path.stat().st_ctime).strftime('%Y-%m-%d %H:%M:%S')
    meta_info.last_access_time = datetime.fromtimestamp(path.stat().st_atime).strftime('%Y-%m-%d %H:%M:%S')
    meta_info.last_modify_time = datetime.fromtimestamp(path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')

    return meta_info

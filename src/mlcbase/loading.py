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
MuLingCloud base module: loading

Support type: json, yaml, xml

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import json
from pathlib import Path
from typing import Optional, Union

import yaml
import xmltodict

from .logger import Logger
from .conifg import ConfigDict
from .misc import is_dict, is_list, is_int

PathLikeType = Union[str, Path]


def load_json(path: PathLikeType, logger: Optional[Logger] = None):
    """load json file to a dict

    Args:
        path (PathLikeType)
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a ConfigDict if success, return None if fail
    """
    assert Path(path).exists(), 'json load error: the file is not exist'
    assert Path(path).suffix == '.json', 'json load error: the suffix must be .json'

    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return ConfigDict(data)
    except OSError as e:
        if logger is not None:
            logger.error(f'json load error: {str(e)}')
        return None
    

def save_json(data: Union[list, dict],
              path: PathLikeType,
              ensure_ascii: bool = True,
              indent: Optional[int] = 4,
              logger: Optional[Logger] = None,):
    """save data to a json file

    Args:
        data (Union[List, Dict])
        path (PathLikeType)
        ensure_ascii (Optional[bool]): when ensure_ascii=False, allow non-ASCII characters in the file. 
                                       Defaults to True.
        indent (Optional[int]): spaces to use for indentation. Defaults to 4.
        logger (Optional[Logger]): Defaults to None.

    Returns:
        bool: return True if success, return False if fail
    """
    assert is_dict(data) or is_list(data), 'json save error: the saving data must be "dict" or "list" type'
    assert Path(path).suffix == '.json', 'json save error: the suffix must be .json'
    if indent is not None:
        assert is_int(indent), 'json save error: the indent must be "int" type'
    
    try:
        with open(path, 'w') as f:
            json.dump(data, f, ensure_ascii=ensure_ascii, indent=indent)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'json save error: {str(e)}')
        return False
    

def load_yaml(path: PathLikeType, logger: Optional[Logger] = None):
    """load yaml file to a dict

    Args:
        path (PathLikeType)
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a ConfigDict if success, return None if fail
    """
    assert Path(path).exists(), 'yaml load error: the file is not exist'
    assert Path(path).suffix == '.yaml', 'yaml load error: the suffix must be .yaml'

    try:
        with open(path, 'r') as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
        return ConfigDict(data)
    except OSError as e:
        if logger is not None:
            logger.error(f'yaml load error: {str(e)}')
        return None
    

def save_yaml(data: dict, 
              path: PathLikeType, 
              allow_unicode: Optional[bool] = None,
              logger: Optional[Logger] = None):
    """save data to a yaml file

    Args:
        data (dict)
        path (PathLikeType)
        allow_unicode (Optional[bool], optional): when allow_unicode=True, allow non-ASCII characters 
                                                  in the file. Defaults to True.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if success, return False if fail
    """
    assert is_dict(data), 'yaml save error: the saving data must be "dict" type'
    assert Path(path).suffix == '.yaml', 'yaml save error: the suffix must be .yaml'

    try:
        with open(path, 'w') as f:
            yaml.dump(data, f, Dumper=yaml.SafeDumper, allow_unicode=allow_unicode)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'yaml save error: {str(e)}')
        return False


def load_xml(path: PathLikeType, logger: Optional[Logger] = None):
    """load xml file to a dict

    Args:
        path (PathLikeType)
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a dict if success, return None if fail
    """
    assert Path(path).exists(), 'xml load error: the file is not exist'
    assert Path(path).suffix == '.xml', 'xml load error: the suffix must be .xml'

    try:
        with open(path, 'r') as f:
            data = f.read()
        data_orderedD = xmltodict.parse(data)
        data_json = json.dumps(data_orderedD, indent=4)
        data_dict = json.loads(data_json)
        return ConfigDict(data_dict)
    except OSError as e:
        if logger is not None:
            logger.error(f'xml load error: {str(e)}')
        return None
    

def save_xml(data: dict, 
             path: PathLikeType, 
             encoding: str = 'utf-8',
             logger: Optional[Logger] = None,):
    """save data to a xml file

    Args:
        data (dict)
        path (PathLikeType)
        encoding (str, optional): Defaults to 'utf-8'.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if success, return False if fail
    """
    assert is_dict(data), 'xml save error: the saving data must be "dict" type'
    assert Path(path).suffix == '.xml', 'xml save error: the suffix must be .xml'

    try:
        xml_data = xmltodict.unparse(data, pretty=True, encoding=encoding)
        with open(path, 'w') as f:
            f.write(xml_data)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'xml save error: {str(e)}')
        return False

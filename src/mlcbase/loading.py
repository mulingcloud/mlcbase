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
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

import yaml

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
    assert Path(path).suffix.lower() == '.json', 'json load error: the suffix must be .json'

    try:
        with open(path, 'r') as f:
            data = json.load(f)
        if is_list(data):
            return data
        else:
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
    assert Path(path).suffix.lower() == '.json', 'json save error: the suffix must be .json'
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
    assert Path(path).suffix.lower() == '.yaml', 'yaml load error: the suffix must be .yaml'

    try:
        with open(path, 'r') as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
        if is_list(data):
            return data
        else:
            return ConfigDict(data)
    except OSError as e:
        if logger is not None:
            logger.error(f'yaml load error: {str(e)}')
        return None
    

def save_yaml(data: Union[dict, list], 
              path: PathLikeType, 
              allow_unicode: bool = False,
              logger: Optional[Logger] = None):
    """save data to a yaml file

    Args:
        data (dict)
        path (PathLikeType)
        allow_unicode (bool, optional): when allow_unicode=True, allow unicode characters 
                                        in the file. Defaults to False.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if success, return False if fail
    """
    assert is_dict(data) or is_list(data), 'yaml save error: the saving data must be "dict" or "list" type'
    assert Path(path).suffix.lower() == '.yaml', 'yaml save error: the suffix must be .yaml'

    try:
        with open(path, 'w') as f:
            yaml.dump(data, f, Dumper=yaml.SafeDumper, allow_unicode=allow_unicode)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'yaml save error: {str(e)}')
        return False
    
    
class _XMLParser:
    def __init__(self, path: PathLikeType):
        tree = ET.parse(path)
        root = tree.getroot()
        self.data = {root.tag: self.__parse_node(root, self.__get_child_nodes_name(root))}

    def __parse_node(self, parent, child_nodes_name):
        data = {}
        for child in parent:
            child_name = child.tag
            child_num = child_nodes_name[child_name]
            if child_num > 1:
                if child_name not in data.keys():
                    data[child_name] = []
                data[child_name].append(self.__parse_node(child, self.__get_child_nodes_name(child)))
            else:
                if self.__has_child(child):
                    data[child_name] = self.__parse_node(child, self.__get_child_nodes_name(child))
                else:
                    data[child_name] = child.text
        return data

    @staticmethod
    def __get_child_nodes_name(parent):
        child_nodes_name = dict()
        for child in parent:
            if child.tag not in child_nodes_name.keys():
                child_nodes_name[child.tag] = 0
            child_nodes_name[child.tag] += 1
        return child_nodes_name
    
    @staticmethod
    def __has_child(parent):
        return len(parent) > 0


def load_xml(path: PathLikeType, logger: Optional[Logger] = None):
    """load xml file to a dict

    Args:
        path (PathLikeType)
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a dict if success, return None if fail
    """
    assert Path(path).exists(), 'xml load error: the file is not exist'
    assert Path(path).suffix.lower() == '.xml', 'xml load error: the suffix must be .xml'

    try:
        parser = _XMLParser(path)
        return ConfigDict(parser.data)
    except OSError as e:
        if logger is not None:
            logger.error(f'xml load error: {str(e)}')
        return None
    

def save_xml(data: dict, 
             path: PathLikeType, 
             encoding: str = 'utf-8',
             pretty: bool = True,
             indent: str = '\t',
             logger: Optional[Logger] = None,):
    """save data to a xml file

    Args:
        data (dict)
        path (PathLikeType)
        encoding (str, optional): Defaults to 'utf-8'.
        pretty (bool, optional): Whether to save formatted XML file. Defaults to True.
        indent (str, optional): Defaults to "\t".
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if success, return False if fail
    """
    def wrap_node(parent: object, node_data: Union[dict, list, str], node_name: str):
        if is_dict(node_data):
            for key, value in node_data.items():
                if is_dict(value):
                    child = ET.SubElement(parent, str(key))
                    wrap_node(child, value, str(key))
                else:
                    wrap_node(parent, value, str(key))
        elif is_list(node_data):
            for sub_data in node_data:
                child = ET.SubElement(parent, str(node_name))
                wrap_node(child, sub_data, str(node_name))
        else:
            child = ET.SubElement(parent, str(node_name))
            child.text = str(node_data)
            
    assert is_dict(data), 'xml save error: the saving data must be "dict" type'
    assert len(list(data.keys())) == 1, "xml save error: data should be a dict with single key"
    assert Path(path).suffix.lower() == '.xml', 'xml save error: the suffix must be .xml'

    try:
        root_name = str(list(data.keys())[0])
        root = ET.Element(root_name)
        wrap_node(root, data[root_name], root_name)
        if pretty:
            xml_string = ET.tostring(root, encoding=encoding)
            formatted_xml = minidom.parseString(xml_string).toprettyxml(indent=indent, encoding=encoding)
            with open(path, 'wb') as f:
                f.write(formatted_xml)
        else:
            tree = ET.ElementTree(root)
            tree.write(path, encoding=encoding)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'xml save error: {str(e)}')
        return False

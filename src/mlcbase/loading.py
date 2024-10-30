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
import toml

from .logger import Logger
from .conifg import ConfigDict
from .register import FILEOPT
from .misc import is_dict, is_list, is_int

PathLikeType = Union[str, Path]


@FILEOPT.register_module()
def load_json(path: PathLikeType, 
              encoding: Optional[str] = None,
              logger: Optional[Logger] = None):
    """load json file to a dict

    Args:
        path (PathLikeType)
        encoding (str, optional): Defaults to None.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a ConfigDict if success, return None if fail
    """
    assert Path(path).exists(), 'json load error: the file is not exist'
    assert Path(path).suffix.lower() == '.json', 'json load error: the suffix must be .json'

    try:
        with open(path, 'r', encoding=encoding) as f:
            data = json.load(f)
        if is_list(data):
            return data
        else:
            return ConfigDict(data)
    except OSError as e:
        if logger is not None:
            logger.error(f'json load error: {str(e)}')
        return None
    

@FILEOPT.register_module()
def save_json(data: Union[list, dict],
              path: PathLikeType,
              ensure_ascii: bool = True,
              indent: Optional[int] = 4,
              encoding: Optional[str] = None,
              logger: Optional[Logger] = None):
    """save data to a json file

    Args:
        data (Union[List, Dict])
        path (PathLikeType)
        ensure_ascii (Optional[bool]): when ensure_ascii=False, allow non-ASCII characters in the file. 
                                       Defaults to True.
        indent (Optional[int]): spaces to use for indentation. Defaults to 4.
        encoding (str, optional): Defaults to None.
        logger (Optional[Logger]): Defaults to None.

    Returns:
        bool: return True if success, return False if fail
    """
    assert is_dict(data) or is_list(data), 'json save error: the saving data must be "dict" or "list" type'
    assert Path(path).suffix.lower() == '.json', 'json save error: the suffix must be .json'
    if indent is not None:
        assert is_int(indent), 'json save error: the indent must be "int" type'
    
    try:
        with open(path, 'w', encoding=encoding) as f:
            json.dump(data, f, ensure_ascii=ensure_ascii, indent=indent)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'json save error: {str(e)}')
        return False
    

@FILEOPT.register_module()
def load_yaml(path: PathLikeType, 
              encoding: Optional[str] = None,
              logger: Optional[Logger] = None):
    """load yaml file to a dict

    Args:
        path (PathLikeType)
        encoding (str, optional): Defaults to None.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a ConfigDict if success, return None if fail
    """
    assert Path(path).exists(), 'yaml load error: the file is not exist'
    assert Path(path).suffix.lower() in [".yml", ".yaml"], 'yaml load error: the suffix must be .yml or .yaml'

    try:
        with open(path, 'r', encoding=encoding) as f:
            data = yaml.load(f, Loader=yaml.SafeLoader)
        if is_list(data):
            return data
        else:
            return ConfigDict(data)
    except OSError as e:
        if logger is not None:
            logger.error(f'yaml load error: {str(e)}')
        return None
    

@FILEOPT.register_module()
def save_yaml(data: Union[dict, list], 
              path: PathLikeType, 
              allow_unicode: bool = False,
              encoding: Optional[str] = None,
              logger: Optional[Logger] = None):
    """save data to a yaml file

    Args:
        data (dict)
        path (PathLikeType)
        allow_unicode (bool, optional): when allow_unicode=True, allow unicode characters 
                                        in the file. Defaults to False.
        encoding (str, optional): Defaults to None.
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if success, return False if fail
    """
    assert is_dict(data) or is_list(data), 'yaml save error: the saving data must be "dict" or "list" type'
    assert Path(path).suffix.lower() in [".yml", ".yaml"], 'yaml save error: the suffix must be .yml or .yaml'

    try:
        with open(path, 'w', encoding=encoding) as f:
            yaml.dump(data, f, Dumper=yaml.SafeDumper, allow_unicode=allow_unicode)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'yaml save error: {str(e)}')
        return False


@FILEOPT.register_module()
def load_xml(path: PathLikeType, logger: Optional[Logger] = None):
    """load xml file to a dict

    Args:
        path (PathLikeType)
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a dict if success, return None if fail
    """
    def has_child(parent):
        return len(parent) > 0
    
    def get_child_nodes_name(parent):
        child_nodes_name = dict()
        for child in parent:
            if child.tag not in child_nodes_name.keys():
                child_nodes_name[child.tag] = 0
            child_nodes_name[child.tag] += 1
        return child_nodes_name
    
    def parse_node(parent, child_nodes_name):
        if has_child(parent):
            data = {}
            for child in parent:
                child_name = child.tag
                child_attrib = child.attrib
                child_num = child_nodes_name[child_name]
                if child_num > 1:
                    if child_name not in data.keys():
                        data[child_name] = []
                    if len(list(child_attrib.keys())) > 0:
                        list_data = {}
                        for k, v in child_attrib.items():
                            list_data[f"@{k}"] = v
                        list_data.update(parse_node(child, get_child_nodes_name(child)))
                        data[child_name].append(list_data)
                    else:
                        data[child_name].append(parse_node(child, get_child_nodes_name(child)))
                else:
                    data[child_name] = {}
                    for k, v in child_attrib.items():
                        data[child_name][f"@{k}"] = v

                    if has_child(child):
                        data[child_name].update(parse_node(child, get_child_nodes_name(child)))
                    else:
                        if len(list(filter(lambda x: x.startswith("@"), data[child_name].keys()))) > 0:
                            data[child_name]["#text"] = child.text
                        else:
                            data[child_name] = child.text
        else:
            attrib = parent.attrib
            if len(list(attrib.keys())) > 0:
                data = {}
                for k, v in attrib.items():
                    data[f"@{k}"] = v
                data['#text'] = parent.text
            else:
                data = parent.text
        return data

    assert Path(path).exists(), 'xml load error: the file is not exist'
    assert Path(path).suffix.lower() == '.xml', 'xml load error: the suffix must be .xml'

    try:
        tree = ET.parse(path)
        root = tree.getroot()
        xml_data = {}
        xml_data[root.tag] = parse_node(root, get_child_nodes_name(root))
        for k, v in root.attrib.items():
            xml_data[root.tag][f"@{k}"] = v
        return ConfigDict(xml_data)
    except OSError as e:
        if logger is not None:
            logger.error(f'xml load error: {str(e)}')
        return None
    

@FILEOPT.register_module()
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
    def wrap_node(parent: object, node_data: Union[dict, list, str], node_name: str, is_root: bool):
        if is_dict(node_data):
            if len(list(filter(lambda x: x.startswith("@"), node_data.keys()))) == len(node_data.keys()):
                raise SyntaxError(f"xml save error: all the node data are attributes without child node "
                                  f"or text: {', '.join(list(node_data.keys()))}")

            if is_root:
                if "#text" in node_data.keys():
                    parent.text = str(node_data["#text"])
                else:
                    for k, v in node_data.items():
                        if k.startswith("@"):
                            continue
                        wrap_node(parent, v, str(k), False)
            else:
                child_attrib_names = list(filter(lambda x: x.startswith("@"), node_data.keys()))
                child_attrib = {}
                for name in child_attrib_names:
                    child_attrib[name[1:]] = node_data[name]
                child = ET.SubElement(parent, str(node_name), attrib=child_attrib)
                if "#text" in node_data.keys():
                    child.text = str(node_data["#text"])
                else:
                    for k, v in node_data.items():
                        if k.startswith("@"):
                            continue
                        wrap_node(child, v, str(k), False)
        elif is_list(node_data):
            for sub_data in node_data:
                wrap_node(parent, sub_data, str(node_name), False)
        else:
            if not is_root:
                child = ET.SubElement(parent, str(node_name))
                child.text = str(node_data)
            else:
                parent.text = str(node_data)
            
    assert is_dict(data), 'xml save error: the saving data must be "dict" type'
    assert len(list(data.keys())) == 1, "xml save error: data should be a dict with single key"
    assert Path(path).suffix.lower() == '.xml', 'xml save error: the suffix must be .xml'

    try:
        root_name = str(list(data.keys())[0])
        if is_dict(data[root_name]):
            root_attrib_names = list(filter(lambda x: x.startswith("@"), data[root_name].keys()))
            root_attrib = {}
            for name in root_attrib_names:
                root_attrib[name[1:]] = data[root_name][name]
            root = ET.Element(root_name, attrib=root_attrib)
            wrap_node(root, data[root_name], root_name, True)
        else:
            root = ET.Element(root_name)
            wrap_node(root, data[root_name], root_name, True)

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


@FILEOPT.register_module()
def load_toml(path: PathLikeType, 
              logger: Optional[Logger] = None):
    """load toml file to a dict

    Args:
        path (PathLikeType)
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        ConfigDict or None: return a ConfigDict if success, return None if fail
    """
    assert Path(path).exists(), 'toml load error: the file is not exist'
    assert Path(path).suffix.lower() == '.toml', 'json load error: the suffix must be .toml'

    try:
        data = toml.load(path)
        return ConfigDict(data)
    except OSError as e:
        if logger is not None:
            logger.error(f'toml load error: {str(e)}')
        return None


@FILEOPT.register_module()
def save_toml(data: dict,
              path: PathLikeType,
              logger: Optional[Logger] = None):
    """save data to a toml file

    Args:
        data (dict)
        path (PathLikeType)
        logger (Optional[Logger], optional): Defaults to None.
    
    Returns:
        bool: return True if success, return False if fail
    """
    assert is_dict(data), 'toml save error: the saving data must be "dict" type'
    assert Path(path).suffix.lower() == ".toml", 'toml save error: the suffix must be .toml'
    try:
        with open(path, 'w', encoding="utf-8") as f:
            toml.dump(data, f)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f'toml save error: {str(e)}')
        return False

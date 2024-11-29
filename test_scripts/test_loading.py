from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import *


def run():
    logger = Logger()
    logger.init_logger()

    module_info = dict(name="mlcbase",
                       repository=dict(github="https://github.com/mulingcloud/mlcbase",
                                       gitlab="https://gitlab.com/wm-chen/mlcbase",
                                       gitee="https://gitee.com/mulingcloud/mlcbase"),
                       author="Weiming Chen",
                       contributors=["Yuanshuang Sun"],
                       location="Chinese Mainland")
    ## json
    logger.info("Testing save and load json...")
    if not save_json(module_info, path="module_info.json", logger=logger):
        raise RuntimeError("Failed to save json")
    if load_json("module_info.json", logger=logger) is None:
        raise RuntimeError("Failed to load json")

    ## yaml
    logger.info("Testing save and load yaml...")
    if not save_yaml(module_info, path="module_info.yaml", logger=logger):
        raise RuntimeError("Failed to save yaml")
    if load_yaml("module_info.yaml", logger=logger) is None:
        raise RuntimeError("Failed to load yaml")

    ## xml
    logger.info("Testing save and load xml...")
    module_info_xml = dict(module=dict(name="mlcbase",
                           repository=dict(github="https://github.com/mulingcloud/mlcbase",
                                           gitlab="https://gitlab.com/wm-chen/mlcbase",
                                           gitee="https://gitee.com/mulingcloud/mlcbase"),
                           author="Weiming Chen",
                           contributors=["Yuanshuang Sun"],
                           location="Chinese Mainland"))
    if not save_xml(module_info_xml, path="module_info.xml", logger=logger):
        raise RuntimeError("Failed to save xml")
    if load_xml("module_info.xml", logger=logger) is None:
        raise RuntimeError("Failed to load xml")
    module_info_with_attr_xml = {"module": {
        "@brand": "MuLingCloud",  # the key name starts with "@" denote to an attribute
        "name": "mlcbase",
        "repository": {"github": "https://github.com/mulingcloud/mlcbase",
                    "gitlab": "https://gitlab.com/wm-chen/mlcbase",
                    "gitee": "https://gitee.com/mulingcloud/mlcbase"},
        "author": {
            "@id": "1", 
            "@role": "leader", 
            "#text": "Weiming Chen"  # use "#text" to represent the text content when the node has attribute(s) but no child node
        },
        "contributors": [
            {"@id": "2", "@role": "collaborator", "#text": "Yuanshuang Sun"},
            {"@id": "3", "@role": "collaborator", "#text": "Zilin Yang"},
        ],
        "location": "Chinese Mainland"
    }}
    if not save_xml(module_info_with_attr_xml, path="module_info_with_attr.xml", logger=logger):
        raise RuntimeError("Failed to save xml with attributes")
    if load_xml("module_info_with_attr.xml", logger=logger) is None:
        raise RuntimeError("Failed to load xml with attributes")

    ## toml
    logger.info("Testing save and load toml...")
    if not save_toml(module_info, path="module_info.toml", logger=logger):
        raise RuntimeError("Failed to save toml")
    if load_toml("module_info.toml", logger=logger) is None:
        raise RuntimeError("Failed to load toml")
    
    remove("module_info.json")
    remove("module_info.yaml")
    remove("module_info.xml")
    remove("module_info_with_attr.xml")
    remove("module_info.toml")
    logger.success("All tests passed!")


if __name__ == "__main__":
    run()

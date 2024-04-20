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
MuLingCloud base module: config dictionary

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
from .misc import is_dict


class ConfigDict(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, *args, **kwargs):
        super(ConfigDict, self).__init__(*args, **kwargs)
        for k, v in self.items():
            if is_dict(v):
                self[k] = self.__parse_to_config_dict(v)

    def __parse_to_config_dict(self, d):
        """parse dict to ConfigDict

        Args:
            d (dict)

        Returns:
            ConfigDict
        """
        for k, v in d.items():
            if is_dict(v):
                d[k] = self.__parse_to_config_dict(v)
        return ConfigDict(d)

    def __missing__(self, key):
        """return None when the key is not exist

        Args:
            key (str): non-existent key

        Returns:
            None
        """
        return None


def is_config_dict(p):
    if isinstance(p, ConfigDict):
        return True
    else:
        return False

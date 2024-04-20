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
MuLingCloud base module: vault api

Support secret engine: kv2

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
from pathlib import Path
from datetime import datetime
from typing import Optional, Union

import hvac

from .logger import Logger

PathLikeType = Union[str, Path]


class VaultAPI:
    def __init__(self, 
                 url: str, 
                 token: str,
                 work_dir: Optional[PathLikeType] = None,
                 logger: Optional[Logger] = None,
                 quiet: bool = True):
        self.work_dir = Path(work_dir) if work_dir is not None else None
        self.logger = self._set_logger(logger, quiet)

        self.__client = self.__connect(url, token)

    def get_secret(self, path: str, key: str, mount_point: str):
        """get secret from vault (for kv v2 secret engine)

        Args:
            path (str): secret path in secrets engine
            key (str)
            mount_point (str): secrets engine's mount point.

        Returns:
            secret value
        """
        if not self.__client.is_authenticated():
            self.__client = self._connect()
        return self.__client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount_point)["data"]["data"][key]

    def __connect(self, url, token):
        client = hvac.Client(url=url, token=token)
        if not client.is_authenticated():
            self.logger.error('vault authentication failed')
            raise ConnectionError('vault authentication failed')
        return client
        
    def _set_logger(self, logger: Optional[Logger], quiet: bool):
        if logger is None:
            now_time = datetime.now().strftime('%Y%m%d-%H%M%S')
            logger = Logger()
            if self.work_dir is not None:
                logger.init_logger(save_path=self.work_dir/'log'/f'{now_time}.log')
            else:
                logger.init_logger()
        if quiet:
            logger.set_quiet()
        else:
            logger.set_activate()
        return logger

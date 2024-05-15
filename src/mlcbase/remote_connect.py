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
MuLingCloud base module: remote connect

Supported OS:
- Linux
- Windows

TODO: support MacOS

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Union, Callable

import paramiko

from .logger import Logger
from .file import listdir, create
from .register import REMOTE
from .misc import PlatformNotSupportError

PathLikeType = Union[str, Path]


@REMOTE.register_module()
class SSH:
    def __init__(self,
                 host: str, 
                 port: int,
                 user: str,
                 password: str,
                 timeout: int = 30,
                 work_dir: Optional[PathLikeType] = None, 
                 logger: Optional[Logger] = None,
                 quiet: bool = False):
        """An api of SSH connection

        Args:
            host (str)
            port (int)
            user (str)
            password (str)
            timeout (int, optional): Defaults to 30 seconds.
            work_dir (Optional[PathLikeType], optional): will save the log file to "work_dir/log/" if 
                                                         work_dir is specified. Defaults to None.
            logger (Optional[Logger], optional): Defaults to None.
            quiet (bool, optional): whether the logger to run in quiet mode. Defaults to False.
        """
        self.work_dir = Path(work_dir) if work_dir is not None else None
        self.logger = self._set_logger(logger, quiet)

        self.__ssh_client = self.__connect(host, port, user, password, timeout)
        
    def __connect(self, host, port, user, password, timeout):
        self.logger.info('ssh connecting to remote server...')
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(host, port, user, password, timeout=timeout)
            self.logger.success('ssh connected to remote server.')
            return ssh_client
        except paramiko.SSHException as e:
            self.logger.error(f"ssh connect error: {str(e)}")
            return None

    def execute(self, 
                command: str, 
                return_str: bool = True,
                encoding: str = "utf-8") -> str:
        """execute command on remote server

        Args:
            command (str)
            return_str (bool, optional): return outputs in str. Defaults to True.
            encoding (str, optional): Defaults to "utf-8".

        Returns:
            object or str: return outputs in str if return_str is True, otherwise return object
        """
        if self.__ssh_client is None:
            self.logger.error('ssh connection is not established.')
            return None
        
        _, stdout, stderr = self.__ssh_client.exec_command(command)

        if return_str:
            stdout = stdout.read().decode(encoding)
            stderr = stderr.read().decode(encoding)

        return stdout, stderr
    
    def close(self):
        if self.__ssh_client is not None:
            self.__ssh_client.close()
            self.logger.info('ssh connection closed')
    
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


@REMOTE.register_module()
class SFTP:
    def __init__(self,
                 host: str, 
                 port: int,
                 user: str,
                 password: str,
                 timeout: int = 30,
                 work_dir: Optional[PathLikeType] = None, 
                 logger: Optional[Logger] = None,
                 quiet: bool = False):
        """An spi of SFTP connection

        Args:
            host (str)
            port (int)
            user (str)
            password (str)
            timeout (int, optional): Defaults to 30 seconds.
            work_dir (Optional[PathLikeType], optional): will save the log file to "work_dir/log/" if 
                                                         work_dir is specified. Defaults to None.
            logger (Optional[Logger], optional): Defaults to None.
            quiet (bool, optional): whether the logger to run in quiet mode. Defaults to False.
        """
        self.work_dir = Path(work_dir) if work_dir is not None else None
        self.logger = self._set_logger(logger, quiet)
        
        self.support_remote_platform = ["windows", "linux"]

        self.__client = self.__connect(host, port, user, password, timeout)
        
    def __connect(self, host, port, user, password, timeout):
        self.logger.info('sftp connecting to remote server...')
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(host, port, user, password, timeout=timeout)
            sftp_client = paramiko.SFTPClient.from_transport(ssh_client.get_transport())
            self.logger.success('sftp connected to remote server.')
            return (sftp_client, ssh_client)
        except paramiko.SSHException as e:
            self.logger.error(f"sftp connect error: {str(e)}")
            return None

    def upload_file(self, 
                    local_path: PathLikeType,
                    remote_path: PathLikeType,
                    remote_platform: str,
                    callback: Optional[Callable] = None):
        """upload a file to remote server

        Args:
            local_path (PathLikeType)
            remote_path (PathLikeType)
            remote_platform (str)
            callback (Optional[Callable], optional): callback function. Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            return False

        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            return False

        remote_path = self.__format_path(remote_path, remote_platform)

        if not Path(local_path).exists():
            self.logger.error('local path does not exist')
            return False

        if Path(local_path).is_dir():
            self.logger.warning('local path is a directory, skipping...')
            return False
        
        self.logger.info(f'uploading file: [LOCAL] {local_path} -> [REMOTE] {remote_path}')
        try:
            self.__client[0].put(local_path, remote_path, callback=callback)
            self.logger.success(f'file uploaded')
            return True
        except paramiko.SFTPError as e:
            self.logger.error(f"sftp upload file error: {str(e)}")
            return False
        
    def download_file(self,
                      remote_path: PathLikeType,
                      local_path: PathLikeType,
                      remote_platform: str,
                      callback: Optional[Callable] = None):
        """download a file from remote server

        Args:
            remote_path (PathLikeType)
            local_path (PathLikeType)
            remote_platform (str)
            callback (Optional[Callable], optional): callback function. Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            return False
        
        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            return False
        
        remote_path = self.__format_path(remote_path, remote_platform)
        
        if not self.remote_exists(remote_path, remote_platform):
            self.logger.error('remote path does not exist')
            return False
        
        if not self.remote_is_file(remote_path, remote_platform):
            self.logger.error('remote path is not a file')
            return False
        
        self.logger.info(f'downloading file: [REMOTE] {remote_path} -> [LOCAL] {local_path}')
        try:
            self.__client[0].get(remote_path, local_path, callback=callback)
            self.logger.success(f'file downloaded')
            return True
        except paramiko.SFTPError as e:
            self.logger.error(f"sftp download file error: {str(e)}")
            return False
        
    def upload_dir(self,
                   local_path: PathLikeType,
                   remote_path: PathLikeType,
                   remote_platform: str,
                   callback: Optional[Callable] = None):
        """upload a directory to remote server

        Args:
            local_path (PathLikeType)
            remote_path (PathLikeType)
            remote_platform (str)
            callback (Optional[Callable], optional): callback function. Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            return False

        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            return False
        
        remote_path = self.__format_path(remote_path, remote_platform)

        if not Path(local_path).exists():
            self.logger.warning('local path does not exist, skipping...')
            return False

        if Path(local_path).is_file():
            self.logger.warning('local path is a file, skipping...')
            return False
        
        self.logger.info(f'uploading directory: [LOCAL] {local_path} -> [REMOTE] {remote_path}')
        try:
            if not self.remote_mkdir(remote_path, remote_platform):
                return False
            
            for p in listdir(local_path, return_path=False, logger=self.logger):
                local_subfile_path = os.path.join(local_path, p)
                remote_subfile_path = os.path.join(remote_path, p)

                if Path(local_subfile_path).is_file():
                    if not self.upload_file(local_subfile_path, remote_subfile_path, remote_platform, callback):
                        self.logger.error(f'failed to upload file: {local_subfile_path} -> {remote_subfile_path}')
                        return False
                    
                if Path(local_subfile_path).is_dir():
                    if not self.upload_dir(local_subfile_path, remote_subfile_path, remote_platform, callback):
                        self.logger.error(f'failed to upload directory: {local_subfile_path} -> {remote_subfile_path}')
                        return False
            
            self.logger.success(f'directory uploaded')
            return True
        except paramiko.SFTPError as e:
            self.logger.error(f"sftp upload directory error: {str(e)}")
            return False
        
    def download_dir(self,
                     remote_path: PathLikeType,
                     local_path: PathLikeType,
                     remote_platform: str,
                     callback: Optional[Callable] = None):
        """download a directory from remote server

        Args:
            remote_path (PathLikeType)
            local_path (PathLikeType)
            remote_platform (str)
            callback (Optional[Callable], optional): callback function. Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            return False
        
        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            return False
        
        remote_path = self.__format_path(remote_path, remote_platform)
        
        if not self.remote_exists(remote_path, remote_platform):
            self.logger.error('remote path does not exist')
            return False
        
        if not self.remote_is_dir(remote_path, remote_platform):
            self.logger.error('remote path is not a directory')
            return False
        
        self.logger.info(f'downloading directory: [REMOTE] {remote_path} -> [LOCAL] {local_path}')
        try:
            if not create(local_path, ftype="dir", logger=self.logger):
                self.logger.error(f'failed to create local directory: {local_path}')
                return False
            
            remote_files = self.remote_listdir(remote_path, remote_platform, return_path=False)
            for f in remote_files:
                remote_subfile_path = os.path.join(remote_path, f)
                local_subfile_path = os.path.join(local_path, f)
                
                if self.remote_is_file(remote_subfile_path, remote_platform):
                    if not self.download_file(remote_subfile_path, local_subfile_path, remote_platform, callback):
                        self.logger.error(f'failed to download file: {remote_subfile_path} -> {local_subfile_path}')
                        return False
                    
                if self.remote_is_dir(remote_subfile_path, remote_platform):
                    if not self.download_dir(remote_subfile_path, local_subfile_path, remote_platform, callback):
                        self.logger.error(f'failed to download directory: {remote_subfile_path} -> {local_subfile_path}')
                        return False
            
            self.logger.success(f'directory downloaded')
            return True
        except paramiko.SFTPError as e:
            self.logger.error(f"sftp download directory error: {str(e)}")
            return False
        
    def remote_exists(self, 
                      remote_path: PathLikeType, 
                      remote_platform: str):
        """check if remote path exists

        Args:
            remote_path (PathLikeType)
            remote_platform (str)

        Raises:
            paramiko.SFTPError: when sftp connection is not established
            PlatformNotSupportError: when remote platform is not supported

        Returns:
            bool: return True if exists, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            raise paramiko.SFTPError('sftp connection is not established')
        
        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            raise PlatformNotSupportError('remote platform is not supported')
        
        remote_path = self.__format_path(remote_path, remote_platform)
        
        try:
            self.__client[0].stat(remote_path)
            return True
        except:
            return False
        
    def remote_is_file(self, 
                       remote_path: PathLikeType, 
                       remote_platform: str):
        """check if remote path is a file

        Args:
            remote_path (PathLikeType)
            remote_platform (str)

        Raises:
            paramiko.SFTPError: when sftp connection is not established
            PlatformNotSupportError: when remote platform is not supported

        Returns:
            bool: return True if the remote path is a file, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            raise paramiko.SFTPError('sftp connection is not established')

        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            raise PlatformNotSupportError('remote platform is not supported')
        
        remote_path = self.__format_path(remote_path, remote_platform)
        
        try:
            self.__client[0].listdir(remote_path)
            return False
        except:
            return True
        
        
    def remote_is_dir(self, 
                      remote_path: PathLikeType, 
                      remote_platform: str):
        """check if remote path is a directory

        Args:
            remote_path (PathLikeType)
            remote_platform (str)

        Raises:
            paramiko.SFTPError: when sftp connection is not established
            PlatformNotSupportError: when remote platform is not supported

        Returns:
            bool: return True if the remote path is a directory, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            raise paramiko.SFTPError('sftp connection is not established')
        
        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            raise PlatformNotSupportError('remote platform is not supported')
        
        remote_path = self.__format_path(remote_path, remote_platform)
        
        try:
            self.__client[0].listdir(remote_path)
            return True
        except:
            return False
        
    def remote_mkdir(self, 
                     remote_path: PathLikeType, 
                     remote_platform: str,
                     exist_ok: bool = True):
        """make a remote directory

        Args:
            remote_path (PathLikeType)
            remote_platform (str)
            exist_ok (bool, optional): if True, the directory will not be created if 
                                       it already exists. Defaults to True.

        Raises:
            paramiko.SFTPError: when sftp connection is not established
            PlatformNotSupportError: when remote platform is not supported

        Returns:
            bool: return True if success, otherwise return False
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            raise paramiko.SFTPError('sftp connection is not established')
        
        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            raise PlatformNotSupportError('remote platform is not supported')
        
        remote_path = self.__format_path(remote_path, remote_platform)
        
        self.logger.info(f'creating remote directory: {remote_path}')
        status = False
        if exist_ok:
            if not self.remote_exists(remote_path, remote_platform):
                try:
                    self.__client[0].mkdir(remote_path)
                    status = True
                except paramiko.SFTPError as e:
                    self.logger.error(f'failed to create directory: {str(e)}')
                    status = False
            else:
                status = True
        else:
            try:
                self.__client[0].mkdir(remote_path)
                status = True
            except paramiko.SFTPError as e:
                self.logger.error(f'failed to create directory: {str(e)}')
                status = False
        
        if status:
            self.logger.success(f'directory created')
        
        return status
    
    def remote_listdir(self,
                       remote_path: PathLikeType, 
                       remote_platform: str,
                       return_path: bool = True):
        """list remote directory

        Args:
            remote_path (PathLikeType)
            remote_platform (str)
            return_path (bool, optional): return the path of the remote file if True, 
                                          otherwise return the name of the remote file. 
                                          Defaults to True.

        Raises:
            paramiko.SFTPError: when sftp connection is not established
            PlatformNotSupportError: when remote platform is not supported

        Returns:
            list or None: return the list of the remote files if success, otherwise return None.
        """
        if self.__client is None:
            self.logger.error('sftp connection is not established')
            raise paramiko.SFTPError('sftp connection is not established')
        
        if remote_platform not in self.support_remote_platform:
            self.logger.error('remote platform is not supported')
            raise PlatformNotSupportError('remote platform is not supported')
        
        remote_path = self.__format_path(remote_path, remote_platform)
        
        try:
            content = self.__client[0].listdir(remote_path)
            if return_path:
                content = [self.__format_path(os.path.join(remote_path, f), remote_platform) for f in content]
            return content
        except paramiko.SFTPError as e:
            self.logger.error(f'failed to list directory: {str(e)}')
            return None

    def close(self):
        if self.__client is not None:
            self.__client[0].close()  # sftp client
            self.__client[1].close()  # ssh client
            self.logger.info('sftp connection closed')
        
    @staticmethod
    def __format_path(path: str, platform: str):
        if platform == 'windows':
            path = path.replace('/', '\\')
        if platform == 'linux':
            path = path.replace('\\', '/')
        return path

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

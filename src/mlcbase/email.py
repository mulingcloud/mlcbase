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
MuLingCloud base module: email api

Support email server: SMTP (SSL)

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Union, List

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.header import Header
from email.utils import formataddr
from email import encoders

from .logger import Logger
from .file import get_file_size
from .conifg import ConfigDict
from .remote_connect import SFTP
from .misc import is_str, is_dict, FileTooLargeError, FileUploadError

PathLikeType = Union[str, Path]


class SMTPAPI:
    def __init__(self, 
                 host: str,
                 port: int,
                 name: str,
                 address: str,
                 password: str,
                 timeout: int = 30,
                 chunk_size: int = 30,  # MB
                 work_dir: Optional[PathLikeType] = None, 
                 logger: Optional[Logger] = None,
                 quiet: bool = False):
        """An api for SMTP server

        Args:
            host (str)
            port (int)
            name (str): sender name
            address (str): sender email address
            password (str): the password or the authorize code
            timeout (int, optional): Defaults to 30 seconds.
            chunk_size (int, optional): large attachment chunk size. if large than the chunk_size, 
                                        the large attachment will upload to the remote sever rather 
                                        than attaching to the email message. Defaults to 30 (MB).
            work_dir (Optional[PathLikeType], optional): will save the log file to "work_dir/log/" if 
                                                         work_dir is specified. Defaults to None.
            logger (Optional[Logger], optional): Defaults to None.
            quiet (bool, optional): whether the logger to run in quiet mode. Defaults to False.
        """
        self.work_dir = Path(work_dir) if work_dir is not None else None
        self.logger = self._set_logger(logger, quiet)
        self.quiet = quiet
        
        self.__name = name
        self.__address = address
        self.__chunk_size = chunk_size
        self.__email_server = self.__connect(host, port, address, password, timeout)
    
    def __connect(self, host, port, address, password, timeout):
        self.logger.info(f"connecting to email server...")
        try:
            email_server = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout)
            email_server.login(user=address, password=password)
            self.logger.success(f"email server connected")
            return email_server
        except smtplib.SMTPException as e:
            self.logger.error(f"email server connect error: {str(e)}")
            return None
        
    def send_email(self, 
                   receiver_name: Union[str, List[str]],
                   receiver_email: Union[str, List[str]],
                   subject: str,
                   content: str,
                   signature: Optional[str] = None,
                   attachment: Optional[Union[PathLikeType, List[PathLikeType]]] = None,
                   remote_server_config: Optional[dict] = None,
                   encoding: str = "utf-8"):
        """send email

        Args:
            receiver_name (Union[str, List[str]])
            receiver_email (Union[str, List[str]])
            subject (str): subject of the email
            content (str): content of the email (will be parsed to html)
            signature (Optional[str], optional): signature at the botom of the email message. Defaults to None.
            attachment (Optional[Union[PathLikeType, List[PathLikeType]]], optional): attachments' path. Defaults to None.
            remote_server_config (Optional[dict], optional): config of the remote server, is required when the large 
                                                             attachments are included. Defaults to None.
            encoding (str, optional): Defaults to "utf-8".
            
        Form of remote_server_config:
        >>> remote_server_config = ConfigDict(host={host of remote server},
        >>>                                   port={port of remote server},
        >>>                                   user={username of remote server},
        >>>                                   password={password of remote server},
        >>>                                   save_director={save director of remote server},
        >>>                                   remote_platform={OS type of remote server},
        >>>                                   url={download base url from remote server})
        You can download the large attachment named "filename" from the remote server via the url:
        >>> url = remote_server_config.url.strip("/") + "/filename"

        Raises:
            smtplib.SMTPException: raise when the email server connection is not established
            FileTooLargeError: raise when you include a large attachment but do not offer the remote server config
            ConnectionError: raise when the remote server connection error
            FileUploadError: raise when the large attachment upload to remote server fail

        Returns:
            bool: return True if the email is sent successfully, otherwise return False
        """
        if self.__email_server is None:
            raise smtplib.SMTPException("email server connection is not established")
        
        assert type(receiver_name) == type(receiver_email), "receiver_name and receiver_email should have the same type"
        if is_str(receiver_name):
            receiver_name = [receiver_name]
            receiver_email = [receiver_email]
        assert len(receiver_name) == len(receiver_email), "receiver_name and receiver_email should have the same length"
        assert remote_server_config is None or is_dict(remote_server_config), \
            "if remote_server_config is not None, it should be a dict"
        if is_dict(remote_server_config):
            remote_server_config = ConfigDict(remote_server_config)
        
        # distinguish attachments with chunk size
        if attachment is not None:
            if is_str(attachment):
                attachment = [attachment]
            
            upload2remote = []
            attach2email = []
            for p in attachment:
                assert Path(p).absolute().exists(), f"{p} not exists"
                assert Path(p).absolute().is_file(), f"{p} is not a file"
                
                if get_file_size(p, return_unit='MB')[0] > self.__chunk_size:
                    if remote_server_config is not None:
                        upload2remote.append(str(Path(p).absolute()))
                    else:
                        self.logger.error(f"{p} is too large")
                        raise FileTooLargeError(f"{p} is too large, please offer 'remote_server_config' \
                            to upload it to remote server via SFTP")
                else:
                    attach2email.append(str(Path(p).absolute()))
                
            has_attachment = True
        else:
            has_attachment = False
        
        # upload large attachment to remote server
        if has_attachment and len(upload2remote) > 0:
            sftp_api = SFTP(host=remote_server_config.host,
                            port=remote_server_config.port,
                            user=remote_server_config.user,
                            password=remote_server_config.password,
                            work_dir=self.work_dir,
                            logger=self.logger,
                            quiet=self.quiet)
            if sftp_api is None:
                raise ConnectionError("remote server connect error")
            
            save_dir = remote_server_config.save_director
            remote_platform = remote_server_config.remote_platform
            callback = remote_server_config.callback

            for p in upload2remote:
                if not sftp_api.upload_file(p, os.path.join(save_dir, Path(p).name), remote_platform, callback):
                    raise FileUploadError(f"{p} upload to remote server error")
            
            sftp_api.close()

        # build email content and attachments
        for name, email in zip(receiver_name, receiver_email):
            message = MIMEMultipart()
            message["From"] = formataddr((self.__name, self.__address))
            message["To"] = formataddr((name, email))
            message["Subject"] = Header(subject, encoding).encode(encoding)

            html_content = self.__format_text(content)

            if has_attachment:
                if len(upload2remote) > 0:
                    html_content += f'<br><br>暂不支持发送超限附件 (<span style="font-weight: bold;">{self.__chunk_size}MB</span>)，' \
                                     '超限附件已上传至远程服务器，请点击以下链接下载：<br>'
                    url = remote_server_config.url.strip("/")
                    for p in upload2remote:
                        html_content += f'<a href="{url}/{Path(p).name}">{Path(p).name}</a><br>'
                
                for p in attach2email:
                    with open(p, "rb") as f:
                        file_msg = MIMEBase("application", "octet-stream")
                        file_msg.set_payload(f.read())
                        encoders.encode_base64(file_msg)
                        file_msg.add_header("Content-Disposition", f"attachment; filename={Path(p).name}")
                        message.attach(file_msg)

            if signature is not None:
                html_content += 4*"<br>" + signature
            
            message.attach(MIMEText(html_content, "html", encoding))

            # send email
            self.logger.info(f"sending email to {name} ({email})...")
            try:
                self.__email_server.sendmail(self.__address, email, message.as_string())
                self.logger.success(f"email sent to {name} ({email})")
            except smtplib.SMTPException as e:
                self.logger.error(f"email send error: {str(e)}")
                return False
        
        return True
            
    def close(self):
        if self.__email_server is not None:
            self.__email_server.quit()
            self.logger.info(f"email server connection closed")
        
    @staticmethod
    def __format_text(text: str) -> str:
        """format text content to html
        replace "\n " and "\n" to "<br>"

        Args:
            text (str)

        Returns:
            str
        """
        text = text.strip("\n").replace("\n ", "<br>")
        text = text.replace("\n", "<br>")
        return text
        
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

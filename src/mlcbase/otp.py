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
MuLingCloud base module: One-time password (OTP) module

Supported method:
- Time-based One-Time Password (TOTP)
- HMAC-based One-Time Password (HOTP)

Author: Weiming Chen
"""
import hashlib
import base64
from io import BytesIO
from pathlib import Path
from datetime import datetime
from typing import Optional, Union

import pyotp
from PIL import Image
from qrcode.main import QRCode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H

from .image_io import load_image
from .conifg import ConfigDict
from .logger import Logger
from .register import SECRET
from .misc import random_otp_secret, is_int, is_url

_OTP_HMAC = {'SHA1': hashlib.sha1,
              'SHA256': hashlib.sha256,
              'SHA512': hashlib.sha512}

PathLikeType = Union[str, Path]


@SECRET.register_module()
def generate_otp_secret(account_name: str, 
                        method: str = "TOTP",
                        issuer: str = "MuLingCloud",
                        algorithm: str = "SHA1",
                        period: int = 30,
                        initial_count: int = 0,
                        digits: int = 6,
                        return_secret_key: bool = True,
                        return_qr_code: bool = True,
                        qr_save_path: Optional[PathLikeType] = None,
                        qr_config: dict = ConfigDict(version=1,
                                                     error_correction=ERROR_CORRECT_M,
                                                     box_size=10,
                                                     border=4,
                                                     fit=True,
                                                     back_color="white",
                                                     fill_color="black",
                                                     has_logo=True,
                                                     logo=None,
                                                     factor=4),
                        logger: Optional[Logger] = None):
    """generate a secret key for OTP (One-time Password) algorithm

    Args:
        account_name (str)
        method (str, optional): OTP method, should be TOTP or HOTP. Defaults to "TOTP".
        issuer (str, optional): Defaults to "MuLingCloud".
        algorithm (str, optional): options have "SHA1", "SHA256", and "SHA512". Defaults to "SHA1".
        period (int, optional): the length of time in seconds used to generate a counter for the 
                                TOTP code calculation. Only used for TOTP. Defaults to 30.
        initial_count (int, optional): starting HMAC counter value. Only used for HOTP method. Defaults to 0.
        digits (int, optional): the number of digits in the generated OTP code. Defaults to 6.
        return_secret_key (bool, optional): whether to return the secret key. Defaults to True.
        return_qr_code (bool, optional): whether to return the QR code in base64 format. Defaults 
                                         to True.
        qr_save_path (Optional[PathLikeType], optional): the path to save the QR code. If None, will not 
                                                         save the QR code. Defaults to None.
        qr_config (Union[dict, ConfigDict], optional): configuration of the QR code.
        logger (Optional[Logger], optional): Defaults to None.

    Raises:
        TypeError: if specifying an unsupported algorithm
        ConnectionError: if the URL of the logo not accessible

    Returns:
        dict: a ConfigDict containing the meta data, secret key (optional), and QR code (optional)
    """
    method = method.upper()
    assert method in ["TOTP", "HOTP"], f'The method parameter should be "TOTP" or "HOTP".'
    if algorithm not in _OTP_HMAC:
        if logger is not None:
            logger.error(f'Algorithm {algorithm} is not supported.')
        raise TypeError(f'Algorithm {algorithm} is not supported.')
    
    secret_key = random_otp_secret()
    if method == "TOTP":
        otp = pyotp.TOTP(secret_key, 
                         digits=digits, 
                         digest=_OTP_HMAC[algorithm], 
                         name=account_name,
                         issuer=issuer,
                         interval=period)
        result = ConfigDict(metadata=dict(method=method, 
                                          issuer=issuer,
                                          account_name=account_name,
                                          algorithm=algorithm,
                                          period=period,
                                          digits=digits))

    if method == "HOTP":
        otp = pyotp.HOTP(secret_key,
                         digits=digits,
                         digest=_OTP_HMAC[algorithm],
                         name=account_name,
                         issuer=issuer,
                         initial_count=initial_count)
        result = ConfigDict(metadata=dict(method=method, 
                                          issuer=issuer,
                                          account_name=account_name,
                                          algorithm=algorithm,
                                          initial_count=initial_count,
                                          digits=digits))
        
    url = otp.provisioning_uri()
    result.url = url

    if return_secret_key:
        result.secret = secret_key
        
    if return_qr_code or qr_save_path is not None:
        qr_config = ConfigDict(qr_config)
        if qr_config.version is not None:
            assert is_int(qr_config.version), f'The version parameter of QRCode should be an integer.'
            assert 1 <= qr_config.version <= 40, f'The version parameter of QRCode should be in [1, 40].'
            
        if qr_config.error_correction is not None:
            assert qr_config.error_correction in [ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H], \
                f"The error_correction parameter of QRCode should be in [{ERROR_CORRECT_L}, {ERROR_CORRECT_M}, " \
                f"{ERROR_CORRECT_Q}, {ERROR_CORRECT_H}]."
            
        has_logo = qr_config.get("has_logo", False)
        if has_logo:
            if qr_config.logo is None:
                # default to use MuLingCloud logo
                qr_config.logo = "https://lychee.weimingchen.net:1130/uploads/original/a6/91/079d600754e4912a218941054741.png"
            else:
                if not Path(qr_config.logo).exists():
                    if not is_url(qr_config.logo):
                        if logger is not None:
                            logger.error(f'The URL {qr_config.logo} is not accessible.')
                        raise ConnectionError(f'The URL {qr_config.logo} is not accessible.')

        qr = QRCode(version=qr_config.get("version", 1),
                    error_correction=qr_config.get("error_correction", ERROR_CORRECT_M),
                    box_size=qr_config.get("box_size", 10),
                    border=qr_config.get("border", 4))
        qr.add_data(url)
        qr.make(fit=qr_config.get("fit", True))
        img = qr.make_image(fill_color=qr_config.get("fill_color", "black"), back_color=qr_config.get("back_color", "white"))

        if has_logo:
            img = img.convert("RGBA")
            logo = load_image(qr_config.logo, return_image=True, backend="pillow", logger=logger)
            factor = qr_config.get("factor", 4)
            logo = logo.resize((img.size[0]//factor, img.size[1]//factor), resample=Image.BILINEAR)
            logo = logo.convert("RGBA")
            img.paste(logo, ((img.size[0]-logo.size[0])//2, (img.size[1]-logo.size[1])//2), logo)
        
        if qr_save_path is not None:
            img.save(qr_save_path)

        if return_qr_code:
            buffer = BytesIO()
            img.save(buffer, format="png")
            byte_data = buffer.getvalue()
            qr_base64 = base64.b64encode(byte_data)
            result.qr_code = qr_base64
        
    return result


@SECRET.register_module()
def generate_otp_code(secret_key: str, 
                      count: Optional[int] = None,
                      method: str = "TOTP",
                      algorithm: str = "SHA1",
                      period: int = 30,
                      initial_count: int = 0,
                      digits: int = 6,
                      logger: Optional[Logger] = None):
    """generate current TOTP code

    Args:
        secret_key (str)
        count (int, optional): OTP HMAC counter. Only used in HOTP method. Defaults to None.
        method (str, optional): OTP method, should be TOTP or HOTP. Defaults to "TOTP".
        algorithm (str, optional): Defaults to "SHA1".
        period (int, optional): Defaults to 30.
        initial_count (int, optional): starting HMAC counter value. Only used for HOTP method. Defaults to 0.
        digits (int, optional): Defaults to 6.
        logger (Optional[Logger], optional): Defaults to None.

    Raises:
        TypeError: if specifying an unsupported algorithm

    Returns:
        str: current TOTP code
    """
    method = method.upper()
    assert method in ["TOTP", "HOTP"], f'The method parameter should be "TOTP" or "HOTP".'
    if algorithm not in _OTP_HMAC:
        if logger is not None:
            logger.error(f'Algorithm {algorithm} is not supported.')
        raise TypeError(f'Algorithm {algorithm} is not supported.')
    
    if method == "TOTP":
        otp = pyotp.TOTP(secret_key,
                         digits=digits,
                         digest=_OTP_HMAC[algorithm],
                         interval=period)
        code = otp.now()
    if method == "HOTP":
        otp = pyotp.HOTP(secret_key,
                         digits=digits,
                         digest=_OTP_HMAC[algorithm],
                         initial_count=initial_count)
        code = otp.at(count)
    return code


@SECRET.register_module()
def verify_otp_code(code: str,
                    secret_key: str,
                    count: Optional[int] = None,
                    method: str = "TOTP",
                    algorithm: str = "SHA1",
                    period: int = 30,
                    initial_count: int = 0,
                    digits: int = 6,
                    for_time: Optional[datetime] = None,
                    valid_window: int = 0,
                    logger: Optional[Logger] = None):
    """verify a code

    Args:
        code (str)
        secret_key (str)
        count (int, optional): OTP HMAC counter. Only used in HOTP method. Defaults to None.
        method (str, optional): OTP method, should be TOTP or HOTP. Defaults to "TOTP".
        algorithm (str, optional): Defaults to "SHA1".
        period (int, optional): Defaults to 30.
        initial_count (int, optional): starting HMAC counter value. Only used for HOTP method. Defaults to 0.
        digits (int, optional): Defaults to 6.
        for_time (Optional[datetime], optional): Time to check OTP at (defaults to now). Only 
                                                 used for TOTP method. Defaults to None.
        valid_window (int, optional): extends the validity to this many counter ticks 
                                      before and after the current one. Only used for TOTP method. 
                                      Defaults to 0.
        logger (Optional[Logger], optional): Defaults to None.

    Raises:
        TypeError: if specifying an unsupported algorithm

    Returns:
        bool: return True if verification succeeded, otherwise return False
    """
    method = method.upper()
    assert is_int(valid_window) and valid_window >= 0, f'The valid_window parameter should be a non-negative integer.'
    assert method in ["TOTP", "HOTP"], f'The method parameter should be "TOTP" or "HOTP".'
    if algorithm not in _OTP_HMAC:
        if logger is not None:
            logger.error(f'Algorithm {algorithm} is not supported.')
        raise TypeError(f'Algorithm {algorithm} is not supported.')

    if method == "TOTP":
        otp = pyotp.TOTP(secret_key,
                         digits=digits,
                         digest=_OTP_HMAC[algorithm],
                         interval=period)
        matched = otp.verify(code, for_time=for_time, valid_window=valid_window)
    if method == "HOTP":
        otp = pyotp.HOTP(secret_key,
                         digits=digits,
                         digest=_OTP_HMAC[algorithm],
                         initial_count=initial_count)
        matched = otp.verify(code, counter=count)

    return matched

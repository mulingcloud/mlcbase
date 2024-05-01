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
MuLingCloud base module: image io module

Author: Weiming Chen
"""
import base64
import requests
from io import BytesIO
from pathlib import Path
from typing import Optional, Any

import cv2
import numpy as np
from PIL import Image

from .logger import Logger
from .conifg import ConfigDict
from .misc import is_url, is_base64


def get_image_from_url(url: str, 
                       save_path: Optional[str] = None,
                       return_bs64: bool = False,
                       return_image: bool = False,
                       backend: str = "cv2",
                       logger: Optional[Logger] = None):
    """get image from url

    Args:
        url (str)
        save_path (Optional[str], optional): Defaults to None.
        return_bs64 (bool, optional): whether to return the image in base64 format. 
                                      Defaults to False.
        return_image (bool, optional): whether to return the image. Defaults to False.
        backend (str, optional): backend of the image. Only used when return_image 
                                 is True. Defaults to "cv2".
        logger (Optional[Logger], optional): Defaults to None.

    Raises:
        ValueError: if the url is invalid or get a error response from the url

    Returns:
        dict: the image in the format of {"image": img, "base64": img_bs64}
    """
    if not is_url(url):
        if logger is not None:
            logger.error(f"Invalid url: {url}")
        raise ValueError(f"Invalid url: {url}")
    assert return_bs64 or return_image, "At least one of return_bs64 and return_image must be True"
    assert backend in ["cv2", "pillow"], f"Invalid backend: {backend}"
    
    response = requests.get(url)
    if response.status_code == 200:
        img_bs64 = response.content

        if save_path is not None:
            with open(save_path, "wb") as f:
                f.write(img_bs64)
        
        image_dict = ConfigDict()
        if return_bs64:
            image_dict.base64 = img_bs64

        if return_image:
            if backend == "cv2":
                img = np.fromstring(img_bs64, np.uint8)
                img = cv2.imdecode(img, cv2.IMREAD_UNCHANGED)
                image_dict.image = img
            
            if backend == "pillow":
                img = BytesIO(img_bs64)
                img = Image.open(img)
                image_dict.image = img

        return image_dict
    else:
        if logger is not None:
            logger.error(f"Failed to get image from url: {url}")
        raise ValueError(f"Failed to get image from url: {url}")


def load_image(path: str, 
               backend: str = "cv2", 
               format: str = "png",
               logger: Optional[Logger] = None):
    """load an image

    Args:
        path (str)
        backend (str, optional): backend of the output image. Defaults to "cv2".
        format (str, optional): saving format of base64. Only used if backend is 
                                base64. Defaults to "png".
        logger (Optional[Logger], optional): Defaults to None.

    Raises:
        FileNotFoundError: if the path of the local image not exists

    Returns:
        np.ndarray or PIL.Image: depends on the backend
    """
    assert backend in ["cv2", "pillow", "base64"], f"Invalid backend: {backend}"

    if Path(path).exists():
        is_local_path = True
    else:
        if not is_url(path):
            if logger is not None:
                logger.error(f"The URL {path} is not accessible.")
            raise ConnectionError(f"The URL {path} is not accessible.")
        is_local_path = False
    
    if is_local_path:
        if backend == "cv2":
            img = cv2.imread(path)
        
        if backend == "pillow":
            img = Image.open(path)

        if backend == "base64":
            img = Image.open(path)
            buffer = BytesIO()
            img.save(buffer, format=format)
            byte_data = buffer.getvalue()
            img = base64.b64encode(byte_data)
    else:
        if backend == "base64":
            img = get_image_from_url(path, return_bs64=True, logger=logger).base64
        else:
            img = get_image_from_url(path, return_image=True, backend=backend, logger=logger).image

    return img


def save_image(img: Any, 
               path: str, 
               backend: str = "cv2", 
               logger: Optional[Logger] = None):
    """save an image to local device

    Args:
        img (Any)
        path (str)
        backend (str, optional): backend of the input image. Defaults to "cv2".
        logger (Optional[Logger], optional): Defaults to None.

    Returns:
        bool: return True if success, otherwise return False
    """
    assert backend in ["cv2", "pillow", "base64"], f"Invalid backend: {backend}"
    
    try:
        if backend == "cv2":
            cv2.imwrite(path, img)
        
        if backend == "pillow":
            img.save(path)
        
        if backend == "base64":
            if not is_base64(img):
                if logger is not None:
                    logger.error("The input image is not in base64 format.")
                raise TypeError("The input image is not in base64 format.")
            
            with open(path, "wb") as f:
                f.write(img)
        return True
    except OSError as e:
        if logger is not None:
            logger.error(f"Failed to save image: {str(e)}")
        return False

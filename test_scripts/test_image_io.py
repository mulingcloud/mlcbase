from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import *


def run():
    logger = Logger()
    logger.init_logger()

    url = "https://www.math.hkust.edu.hk/~masyleung/Teaching/CAS/MATLAB/image/images/barbara.jpg"
    logger.info("Testing download image from internet...")
    get_image_from_url(url, save_path="internet_image.jpg", logger=logger)

    logger.info("Testing read and save image from file...")
    logger.info("Testing cv2 backend...")
    image = load_image("internet_image.jpg", backend="cv2", logger=logger)
    if not save_image(image, path="image_cv2.jpg", backend="cv2", logger=logger):
        raise RuntimeError("Failed to save image using cv2 backend")
    logger.info("Testing PIL backend...")
    image = load_image("internet_image.jpg", backend="pillow", logger=logger)
    if not save_image(image, path="image_pillow.jpg", backend="pillow", logger=logger):
        raise RuntimeError("Failed to save image using pillow backend")
    logger.info("Testing matplotlib backend...")
    image = load_image("internet_image.jpg", backend="plt", logger=logger)
    if not save_image(image, path="image_plt.jpg", backend="plt", logger=logger):
        raise RuntimeError("Failed to save image using plt backend")
    logger.info("Testing base64 backend...")
    image = load_image("internet_image.jpg", backend="base64", logger=logger)
    if not save_image(image, path="image_base64.jpg", backend="base64", logger=logger):
        raise RuntimeError("Failed to save image using base64 backend")
    
    remove("internet_image.jpg")
    remove("image_cv2.jpg")
    remove("image_pillow.jpg")
    remove("image_plt.jpg")
    remove("image_base64.jpg")
    logger.success("All tests passed!")



if __name__ == "__main__":
    run()

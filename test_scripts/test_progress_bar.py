import time
from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import EmojiProgressBar


def run():
    with EmojiProgressBar(total=100) as pbar:
        for _ in range(100):
            time.sleep(0.1)
            pbar.update(1)


if __name__ == "__main__":
    run()

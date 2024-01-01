import os
import sys

def get_correct_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

images = os.path.join('images', 'restbl.ico')
images = get_correct_path(images)
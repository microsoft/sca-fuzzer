# flake8: noqa
# pylint: skip-file

import os

def get_plugin_path() -> str:
    """
    Return the path of the gdb plugin
    """
    return os.path.abspath(os.path.dirname(__file__))

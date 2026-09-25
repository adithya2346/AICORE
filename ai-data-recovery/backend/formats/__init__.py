"""
Plugin registry for all forensic format analyzers.
"""
from typing import Dict, Optional, List
from backend.formats.base import FormatPlugin
from backend.formats.jpeg import JPEGPlugin
from backend.formats.png import PNGPlugin
from backend.formats.pdf import PDFPlugin
from backend.formats.zip import ZIPPlugin
from backend.formats.mp4 import MP4Plugin
from backend.formats.mp3 import MP3Plugin
from backend.formats.sqlite import SQLitePlugin

FORMAT_PLUGINS: Dict[str, FormatPlugin] = {
    "jpeg": JPEGPlugin(),
    "png": PNGPlugin(),
    "pdf": PDFPlugin(),
    "zip": ZIPPlugin(),
    "mp4": MP4Plugin(),
    "mp3": MP3Plugin(),
    "sqlite": SQLitePlugin()
}

def get_format_plugin(format_name: str) -> Optional[FormatPlugin]:
    name = format_name.lower().strip()
    if name in ("jpg", "jpeg"):
        return FORMAT_PLUGINS["jpeg"]
    if name in ("docx", "xlsx"):
        return FORMAT_PLUGINS["zip"]
    return FORMAT_PLUGINS.get(name)

def detect_format_plugin(data: bytes) -> Optional[FormatPlugin]:
    for plugin in FORMAT_PLUGINS.values():
        if plugin.detect(data):
            return plugin
    return None

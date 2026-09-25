import sys
import os
import runpy
from pathlib import Path

pkg_dir = Path(__file__).resolve().parent / "ai-data-recovery"
target = pkg_dir / "desktop_app.py"

if str(pkg_dir) not in sys.path:
    sys.path.insert(0, str(pkg_dir))

os.chdir(pkg_dir)

if __name__ == "__main__":
    runpy.run_path(str(target), run_name="__main__")


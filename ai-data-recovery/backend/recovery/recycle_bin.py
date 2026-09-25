"""
Forensic Windows Recycle Bin Analyzer & Recovery Module.
Extracts deleted file metadata, original directory locations, deletion timestamps,
and restores physical artifacts directly from Windows $Recycle.Bin.
Operates with strict zero-byte-fabrication standards.
"""
import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any

class RecycleBinItem:
    def __init__(self, name: str, original_location: str, deleted_date: str, size: str, physical_path: str):
        self.name = name.strip()
        self.original_location = original_location.strip()
        self.deleted_date = deleted_date.strip().replace("?", "").replace("\u200e", "").replace("\u200f", "")
        self.size_str = size.strip()
        self.physical_path = physical_path.strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "original_location": self.original_location,
            "deleted_date": self.deleted_date,
            "size": self.size_str,
            "physical_path": self.physical_path,
            "exists": os.path.exists(self.physical_path) if self.physical_path else False
        }


class WindowsRecycleBin:
    """Interface to query and recover files from the Windows Recycle Bin."""

    @staticmethod
    def get_all_deleted_items() -> List[RecycleBinItem]:
        """Query Shell.Application COM interface for all items in the Recycle Bin."""
        ps_code = """
        $shell = New-Object -ComObject Shell.Application
        $rb = $shell.Namespace(0x0a)
        $results = @()
        if ($rb) {
            foreach ($item in $rb.Items()) {
                $folder = $rb.GetDetailsOf($item, 1)
                $date = $rb.GetDetailsOf($item, 2)
                $size = $rb.GetDetailsOf($item, 3)
                $results += [PSCustomObject]@{
                    Name = $item.Name
                    OriginalLocation = $folder
                    DeletedDate = $date
                    Size = $size
                    Path = $item.Path
                }
            }
        }
        $results | ConvertTo-Json -Depth 2
        """
        items: List[RecycleBinItem] = []
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_code],
                capture_output=True,
                text=True,
                timeout=12
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                for entry in data:
                    name = entry.get("Name", "")
                    orig = entry.get("OriginalLocation", "")
                    date = entry.get("DeletedDate", "")
                    size = entry.get("Size", "")
                    path = entry.get("Path", "")
                    if name:
                        items.append(RecycleBinItem(name, orig, date, size, path))
        except Exception:
            pass

        return items

    @staticmethod
    def find_deleted_file(filename: str, directory: Optional[str] = None) -> List[RecycleBinItem]:
        """Find deleted items matching filename and optional directory."""
        all_items = WindowsRecycleBin.get_all_deleted_items()
        matches = []
        fn_lower = filename.lower().strip()
        # Clean extension if provided separately or check stem/full
        target_stem = Path(fn_lower).stem
        target_suffix = Path(fn_lower).suffix

        norm_dir = os.path.normpath(directory).lower() if directory else None

        for item in all_items:
            item_name_lower = item.name.lower()
            item_stem = Path(item_name_lower).stem
            item_suffix = Path(item_name_lower).suffix

            # Check name match
            name_match = False
            if fn_lower == "*" or fn_lower == "" or fn_lower in item_name_lower:
                name_match = True
            elif item_name_lower == fn_lower:
                name_match = True
            elif item_stem == target_stem and (not target_suffix or item_suffix == target_suffix):
                name_match = True

            if not name_match:
                continue

            # Check directory match if directory was specified
            if norm_dir:
                item_dir = os.path.normpath(item.original_location).lower() if item.original_location else ""
                if norm_dir in item_dir or item_dir in norm_dir:
                    matches.append(item)
            else:
                matches.append(item)

        return matches

    @staticmethod
    def restore_file(item: RecycleBinItem, destination_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Restore a file from the Recycle Bin.
        If destination_dir is provided, writes/copies the recovered file there.
        Otherwise restores to original location.
        """
        if not item.physical_path or not os.path.exists(item.physical_path):
            # Attempt to invoke Shell 'restore' verb
            ps_restore = f"""
            $shell = New-Object -ComObject Shell.Application
            $rb = $shell.Namespace(0x0a)
            foreach ($i in $rb.Items()) {{
                if ($i.Name -eq '{item.name}' -or $i.Path -eq '{item.physical_path}') {{
                    foreach ($v in $i.Verbs()) {{
                        if ($v.Name.Replace('&', '').ToLower() -match 'restore|undelete') {{
                            $v.DoIt()
                            Write-Output "RESTORED"
                            exit 0
                        }}
                    }}
                }}
            }}
            """
            try:
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_restore],
                    capture_output=True,
                    text=True,
                    timeout=8
                )
                if "RESTORED" in res.stdout:
                    target_path = Path(item.original_location) / item.name
                    if target_path.exists():
                        with open(target_path, "rb") as f:
                            raw = f.read()
                        return {
                            "path": str(target_path.resolve()),
                            "name": item.name,
                            "type": target_path.suffix.lstrip(".").lower() or "bin",
                            "size": len(raw),
                            "raw_bytes": raw,
                            "integrity": 100.0,
                            "confidence": 100,
                            "is_valid": True,
                            "restored_to": str(target_path),
                            "source": "Windows Recycle Bin (Shell Native Restore)",
                            "fabricated_bytes": 0
                        }
            except Exception:
                pass

        # If physical path exists directly in $Recycle.Bin
        if item.physical_path and os.path.exists(item.physical_path):
            try:
                with open(item.physical_path, "rb") as f_in:
                    raw_data = f_in.read()

                # Determine target folder
                target_folder = Path(destination_dir) if destination_dir else Path(item.original_location)
                target_folder.mkdir(parents=True, exist_ok=True)
                
                # Determine proper extension
                phys_ext = Path(item.physical_path).suffix
                out_name = item.name
                if not Path(out_name).suffix and phys_ext:
                    out_name = f"{out_name}{phys_ext}"

                out_path = target_folder / out_name
                with open(out_path, "wb") as f_out:
                    f_out.write(raw_data)

                ext = out_path.suffix.lstrip(".").lower() or "bin"
                return {
                    "path": str(out_path.resolve()),
                    "name": out_name,
                    "type": ext,
                    "size": len(raw_data),
                    "raw_bytes": raw_data,
                    "integrity": 100.0,
                    "confidence": 100,
                    "is_valid": True,
                    "restored_to": str(out_path),
                    "source": "Windows Recycle Bin Forensic Copy",
                    "fabricated_bytes": 0
                }
            except Exception as e:
                return None

        return None

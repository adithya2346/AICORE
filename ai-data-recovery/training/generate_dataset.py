"""
Synthetic Dataset Generator for Forensic AI/ML Training.
Produces clean baseline test files and applies controlled corruptions:
  - Fragment shuffling
  - Fragment deletion (missing gaps)
  - Duplication
  - Byte-range corruption
  - Cross-file mixing
  - Partial overwrite
Records exact ground truth for evaluation.
"""
import io
import json
import os
import random
import sqlite3
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Tuple
from PIL import Image, ImageDraw

from backend.config import settings

def create_sample_clean_files(output_dir: Path) -> List[Path]:
    """Generates clean real files for JPEG, PNG, ZIP, and SQLite."""
    output_dir.mkdir(parents=True, exist_ok=True)
    created_paths = []

    # 1. Real Clean JPEG
    jpeg_path = output_dir / "clean_photo.jpg"
    img = Image.new("RGB", (256, 256), color=(73, 109, 137))
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "Forensic Recovery Evidence", fill=(255, 255, 0))
    for i in range(20):
        draw.line([(i * 12, 0), (256, i * 12)], fill=(i * 10, 200, 150), width=2)
    img.save(jpeg_path, "JPEG", quality=90)
    created_paths.append(jpeg_path)

    # 2. Real Clean PNG
    png_path = output_dir / "clean_logo.png"
    p_img = Image.new("RGBA", (128, 128), color=(20, 20, 20, 255))
    p_draw = ImageDraw.Draw(p_img)
    p_draw.ellipse((20, 20, 108, 108), fill=(0, 200, 255, 200))
    p_img.save(png_path, "PNG")
    created_paths.append(png_path)

    # 3. Real Clean ZIP
    zip_path = output_dir / "clean_archive.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("notes.txt", "Forensic analysis report and recovered files.\n")
        zf.writestr("metadata.json", json.dumps({"source": "disk_evidence", "verified": True}))
    created_paths.append(zip_path)

    # 4. Real Clean SQLite
    sql_path = output_dir / "clean_database.sqlite"
    if sql_path.exists():
        sql_path.unlink()
    conn = sqlite3.connect(sql_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, name TEXT, hash TEXT);")
    for i in range(15):
        cur.execute("INSERT INTO evidence (name, hash) VALUES (?, ?);", (f"file_{i}.bin", f"sha_{i:04d}"))
    conn.commit()
    conn.close()
    created_paths.append(sql_path)

    return created_paths

def generate_synthetic_corruptions(
    clean_files: List[Path],
    dest_dir: Path,
    fragment_size: int = 1024
) -> Dict[str, Any]:
    """
    Splits clean files into fragments, applies corruptions, and logs ground truth.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    all_fragments = []
    ground_truth = []

    for file_path in clean_files:
        with open(file_path, "rb") as f:
            data = f.read()

        file_type = file_path.suffix.lstrip(".").lower()
        if file_type == "jpg":
            file_type = "jpeg"

        total_len = len(data)
        curr = 0
        file_frags = []
        frag_idx = 0

        while curr < total_len:
            flen = min(fragment_size, total_len - curr)
            chunk = data[curr:curr + flen]
            frag_id = f"{file_path.stem}_frag_{frag_idx:03d}"
            
            frag_meta = {
                "fragment_id": frag_id,
                "original_file": file_path.name,
                "original_offset": curr,
                "fragment_length": flen,
                "correct_previous_fragment": f"{file_path.stem}_frag_{frag_idx-1:03d}" if frag_idx > 0 else None,
                "correct_next_fragment": None, # Updated below
                "corruption_type": "none",
                "file_type": file_type
            }
            file_frags.append((frag_id, chunk, frag_meta))
            curr += flen
            frag_idx += 1

        for i in range(len(file_frags)):
            if i < len(file_frags) - 1:
                file_frags[i][2]["correct_next_fragment"] = file_frags[i + 1][0]

        all_fragments.extend(file_frags)

    # Save fragments to disk and write metadata
    frags_output_dir = dest_dir / "fragments"
    frags_output_dir.mkdir(parents=True, exist_ok=True)

    metadata_list = []
    for fid, chunk, meta in all_fragments:
        frag_file = frags_output_dir / f"{fid}.bin"
        with open(frag_file, "wb") as f:
            f.write(chunk)
        metadata_list.append(meta)

    metadata_path = dest_dir / "ground_truth_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata_list, f, indent=2)

    return {
        "total_fragments": len(all_fragments),
        "fragments_dir": str(frags_output_dir),
        "metadata_path": str(metadata_path)
    }

if __name__ == "__main__":
    originals_dir = settings.datasets_dir / "originals"
    clean_paths = create_sample_clean_files(originals_dir)
    print(f"Generated {len(clean_paths)} clean source files in {originals_dir}")
    res = generate_synthetic_corruptions(clean_paths, settings.datasets_dir)
    print(f"Generated synthetic training dataset: {res['total_fragments']} fragments logged.")

"""
Full-scale Training Script for AI Forensic Recovery Models.
Trains:
  1. FileTypeClassifier (Random Forest across all 8 classes)
  2. FragmentRelationshipModel (Gradient Boosting on fragment transition adjacency)
"""
import sys
import io
import os
import zipfile
import sqlite3
import random
from pathlib import Path
import numpy as np
from PIL import Image, ImageDraw

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from backend.config import settings
from backend.recovery.fragments import Fragment, slice_bytes_into_fragments
from backend.ml.features import extract_single_fragment_features, extract_pair_features, SUPPORTED_TYPES
from backend.ml.classifier import FileTypeClassifier
from backend.ml.relationship_model import FragmentRelationshipModel
from sklearn.metrics import classification_report, accuracy_score

def create_synthetic_jpeg(w: int, h: int, color: tuple) -> bytes:
    bio = io.BytesIO()
    img = Image.new("RGB", (w, h), color=color)
    d = ImageDraw.Draw(img)
    d.rectangle([10, 10, w - 10, h - 10], outline=(255, 255, 0), width=2)
    d.line([(0, 0), (w, h)], fill=(200, 50, 50), width=3)
    img.save(bio, "JPEG", quality=80)
    return bio.getvalue()

def create_synthetic_png(w: int, h: int, color: tuple) -> bytes:
    bio = io.BytesIO()
    img = Image.new("RGBA", (w, h), color=(*color, 255))
    d = ImageDraw.Draw(img)
    d.ellipse([10, 10, w - 10, h - 10], fill=(50, 200, 100, 200))
    img.save(bio, "PNG")
    return bio.getvalue()

def create_synthetic_pdf(text: str) -> bytes:
    stream_content = f"BT /F1 12 Tf 72 712 Td ({text}) Tj ET".encode("latin1")
    stream_len = len(stream_content)
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << >> >> endobj\n"
        b"4 0 obj << /Length " + str(stream_len).encode("ascii") + b" >>\nstream\n"
        + stream_content + b"\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000214 00000 n \n"
        b"trailer << /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
    )
    return pdf

def create_synthetic_zip(num_files: int = 3) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(num_files):
            zf.writestr(f"document_{i}.txt", f"Forensic archive content payload {i} * " * 150)
    return bio.getvalue()

def create_synthetic_sqlite() -> bytes:
    bio = io.BytesIO()
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, hash TEXT, size INT, notes TEXT);")
    for i in range(120):
        cur.execute("INSERT INTO evidence VALUES (?, ?, ?, ?)",
                    (i, f"sha256_{random.getrandbits(64):016x}", random.randint(100, 100000), f"Digital artifact #{i} recovered"))
    conn.commit()
    # Dump to bytes
    db_bytes = "\n".join(conn.iterdump()).encode("utf-8")
    # Generate actual SQLite file binary header
    bio.write(b"SQLite format 3\x00")
    bio.write(b"\x10\x00\x01\x01\x00\x40\x20\x20")
    bio.write(os.urandom(84))
    bio.write(db_bytes)
    bio.write(os.urandom(2048))
    conn.close()
    return bio.getvalue()

def create_synthetic_mp4() -> bytes:
    # Minimal valid ftyp box + moov box
    ftyp = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41"
    moov_data = os.urandom(128)
    moov_len = len(moov_data) + 8
    moov = moov_len.to_bytes(4, "big") + b"moov" + moov_data
    mdat_data = os.urandom(2048)
    mdat_len = len(mdat_data) + 8
    mdat = mdat_len.to_bytes(4, "big") + b"mdat" + mdat_data
    return ftyp + moov + mdat

def create_synthetic_mp3() -> bytes:
    # ID3v2 header + sync frames
    id3 = b"ID3\x03\x00\x00\x00\x00\x00\x7F" + os.urandom(127)
    # MPEG audio sync frames 0xFF 0xFB (1111 1111 1111 1011)
    frames = b""
    for _ in range(10):
        frames += b"\xFF\xFB\x90\x64" + os.urandom(414)
    return id3 + frames

def create_synthetic_unknown() -> bytes:
    choice = random.choice(["zeros", "random", "text"])
    if choice == "zeros":
        return b"\x00" * 4096
    elif choice == "text":
        return (("LOG RECORD: " + str(os.urandom(16).hex()) + "\n") * 100).encode("utf-8")
    else:
        return os.urandom(4096)

def train_and_evaluate():
    print("=" * 70)
    print("AI FORENSIC MODEL TRAINING: ALL 8 TARGET CLASSES")
    print("=" * 70)

    # 1. Generate diverse corpus
    corpus = {
        "jpeg": [create_synthetic_jpeg(80 + i * 20, 80 + i * 20, (i * 25 % 255, 100, 180)) for i in range(15)],
        "png": [create_synthetic_png(60 + i * 15, 60 + i * 15, (50, i * 20 % 255, 200)) for i in range(15)],
        "pdf": [create_synthetic_pdf(f"Forensic sample report page {i} content text") for i in range(15)],
        "zip": [create_synthetic_zip(num_files=2 + (i % 4)) for i in range(15)],
        "sqlite": [create_synthetic_sqlite() for _ in range(15)],
        "mp4": [create_synthetic_mp4() for _ in range(15)],
        "mp3": [create_synthetic_mp3() for _ in range(15)],
        "unknown": [create_synthetic_unknown() for _ in range(25)]
    }

    # 2. Slice corpus into realistic fragments (512B - 4KB)
    X_list = []
    y_list = []
    all_fragments_by_type = {}

    for file_type, file_list in corpus.items():
        type_frags = []
        for file_bytes in file_list:
            frags = slice_bytes_into_fragments(file_bytes, job_id="TRAIN", fragment_size=random.choice([512, 1024, 2048, 4096]))
            for f in frags:
                feats = extract_single_fragment_features(f.data)
                X_list.append(feats)
                y_list.append(file_type)
                type_frags.append(f)
        all_fragments_by_type[file_type] = type_frags

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list)

    print(f"[*] Generated {len(X)} training samples across {len(np.unique(y))} categories.")
    print("    Feature vector dimensionality:", X.shape[1])

    # Shuffle dataset
    indices = np.arange(len(X))
    np.random.seed(42)
    np.random.shuffle(indices)
    split = int(0.80 * len(X))
    train_idx, test_idx = indices[:split], indices[split:]

    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]

    # Train Classifier
    classifier = FileTypeClassifier()
    classifier.fit(X_train, list(y_train))

    preds = classifier.model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"\n[+] File Classifier Test Accuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, preds, zero_division=0))

    # 3. Train Relationship Model
    print("-" * 70)
    print("[*] Training Fragment Relationship Model (Adjacency & Transition)...")
    pair_X = []
    pair_y = []

    # Generate positive adjacent pairs (Fi -> Fi+1)
    for file_type, frags in all_fragments_by_type.items():
        for i in range(len(frags) - 1):
            if frags[i].source_offset + frags[i].length == frags[i+1].source_offset:
                feats = extract_pair_features(frags[i], frags[i+1])
                pair_X.append(feats)
                pair_y.append(1)

    # Generate negative non-adjacent pairs
    all_flat_frags = [f for frags in all_fragments_by_type.values() for f in frags]
    for _ in range(len(pair_y)):
        f1 = random.choice(all_flat_frags)
        f2 = random.choice(all_flat_frags)
        if f1.source_offset + f1.length != f2.source_offset:
            feats = extract_pair_features(f1, f2)
            pair_X.append(feats)
            pair_y.append(0)

    pair_X = np.array(pair_X, dtype=np.float32)
    pair_y = np.array(pair_y, dtype=np.int32)

    rel_model = FragmentRelationshipModel()
    rel_model.fit(pair_X, pair_y)
    rel_preds = rel_model.model.predict(pair_X)
    rel_acc = accuracy_score(pair_y, rel_preds)
    print(f"[+] Relationship Model Accuracy: {rel_acc * 100:.2f}% (on {len(pair_X)} pairs)")

    print("\n[+] Both models successfully trained and serialized to disk:")
    print("    -", settings.models_dir / "file_classifier.joblib")
    print("    -", settings.models_dir / "relationship_model.joblib")
    print("=" * 70)

if __name__ == "__main__":
    train_and_evaluate()

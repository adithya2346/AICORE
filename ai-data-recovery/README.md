# AI-Assisted Intelligent Data Recovery & Digital Evidence Reconstruction System

A functional, real-world forensic data recovery platform powered by machine learning, graph theory, and deterministic binary analysis. 

> **CRITICAL FORENSIC INVARIANT:**
> The system **never** invents, hallucinates, or fabricates missing binary data.
> The metric `fabricated_bytes` is mathematically and architecturally guaranteed to be **strictly 0**.
> When data is missing, the system explicitly reports missing offsets, estimated sizes, and recoverability boundaries.

---

## Architecture Pipeline

```
Evidence Acquisition (FileSource / DiskImageSource / PartitionSource)
  │ [Strict Read-Only Handle & SHA-256 Custody Hash]
  ▼
Filesystem Analysis (Read-Only NTFS / FAT32 / exFAT Parser)
  │ [MFT Records, Fixup Arrays, Run-Lists, 0xE5 Deleted Directory Entries]
  ▼
Raw Storage Scanner & Signature Carver (Streaming, Low-Memory mmap)
  │ [JPEG, PNG, PDF, ZIP, DOCX, XLSX, MP4, MP3, SQLite]
  ▼
Fragment Extraction & Feature Engineering
  │ [256-Bin Histograms, Shannon Entropy, Bigrams, Boundary Transitions, Magic Bytes]
  ▼
AI Model 1: File Type Classifier (RandomForest / GradientBoosting)
  │
AI Model 3: Fragment Embeddings & Multi-File Clustering (DBSCAN)
  │
AI Model 2: Fragment Relationship Model (Successor Probability P(A -> B))
  │
Relationship Graph (NetworkX Directed Graph + Beam Search Traversal)
  │
Sequence Scoring & Reconstruction Engine
  │ [Assembles Real Original Bytes; Evaluates Formats & Penalties]
  ▼
Format Validation Engine (Pillow, CRC-32, PDF XREF, ZIP testzip, SQLite QuickCheck)
  │
Technical Confidence & Recoverability Assessment
  │ [model_confidence, file_integrity, recoverability_score, 0 fabricated_bytes]
  ▼
Forensic Audit Report & Reconstructed Artifacts
```

---

## Key Features

1. **Two Core Operational Modes**:
   - **Mode A: Damaged / Corrupted File Recovery**: Carves valid fragments, models successor probabilities, re-aligns markers, and reconstructs intact files.
   - **Mode B: Deleted File Recovery**: Analyzes filesystem metadata (NTFS MFT records, FAT32 directory tables, exFAT streams) and falls back to raw unallocated storage carving.
2. **Three AI / ML Models**:
   - **AI Model 1 (File Classifier)**: Predicts fragment type (`jpeg`, `png`, `pdf`, `zip`, `mp4`, `mp3`, `sqlite`) from statistical and entropy features.
   - **AI Model 2 (Fragment Relationship Model)**: Predicts the probability of Fragment B being the correct successor of Fragment A.
   - **AI Model 3 (Fragment Embeddings)**: Normalized 64-dimensional latent representations for multi-file fragment separation.
3. **Forensic Evidence Handling**:
   - Strictly read-only source handles (`'rb'`).
   - Streaming SHA-256 verification before analysis.
   - Audit logging of all acquisition and processing events.
4. **Deep Format Parsers**:
   - **JPEG**: Marker parser (SOI, APPn, DQT, DHT, SOF0/2, SOS, EOI), entropy-coded scan segment analysis, byte-stuffing validation, and Pillow verification.
   - **PNG**: 8-byte signature, chunk walking (IHDR, IDAT, IEND), and CRC-32 checksums.
   - **PDF**: `%PDF-` header, object dictionaries, cross-reference (`xref`) tables, trailers, and `%%EOF`.
   - **ZIP / DOCX / XLSX**: Local file headers, Central Directory, EOCD, and `zipfile.testzip()` validation.
   - **MP4**: ISO Base Media File Format atom/box parser (`ftyp`, `moov`, `mdat`).
   - **MP3**: ID3v2 tags and MPEG audio sync frame sequences.
   - **SQLite**: Database header, page size validation, and schema verification.
5. **Interactive UI Dashboard**:
   - Built-in web dashboard served at `http://localhost:8000/` with live stage progress, fragment topology explorer, candidate sequence tables, image previews, and audit report downloads.
   - Standalone React + TypeScript + Tailwind CSS application in `frontend/`.

---

## Directory Structure

```
ai-data-recovery/
├── backend/
│   ├── main.py                  # FastAPI server & route orchestration
│   ├── config.py                # System settings & workspace paths
│   ├── database/
│   │   ├── database.py          # SQLAlchemy session setup
│   │   └── models.py            # ORM models (Jobs, Audits, Fragments, Candidates)
│   ├── api/
│   │   ├── recovery.py          # /start, /upload, manual stage triggers
│   │   ├── status.py            # /status, /jobs, /cancel
│   │   └── results.py           # /fragments, /results, /report, /download
│   ├── storage/
│   │   ├── base.py              # Read-only StorageSource interface
│   │   ├── file_source.py       # Single damaged/uploaded file source
│   │   ├── disk_image.py        # Raw disk image source (.dd, .raw, .img) with MBR discovery
│   │   └── partition.py         # Partition slice source
│   ├── filesystem/
│   │   ├── base.py              # Read-only FileSystemAnalyzer interface
│   │   ├── ntfs.py              # NTFS boot sector, MFT parser, run-list decoder
│   │   ├── fat32.py             # FAT32 BPB, directory clusters, 0xE5 deleted marks
│   │   └── exfat.py             # exFAT VBR, directory sets, stream extensions
│   ├── recovery/
│   │   ├── signatures.py        # Signature database & structural markers
│   │   ├── scanner.py           # Streaming raw storage scanner & entropy calculator
│   │   ├── carving.py           # Header/footer correlation file carver
│   │   ├── fragments.py         # Fragment dataclass & slicing utilities
│   │   ├── reconstruction.py    # NetworkX directed graph & beam search assembler
│   │   ├── validation.py        # Central validation engine
│   │   └── confidence.py        # Metric separation (model, integrity, recoverability)
│   ├── formats/
│   │   ├── base.py              # FormatPlugin abstract base & ValidationResult
│   │   ├── jpeg.py              # Full JPEG forensic parser & Pillow validator
│   │   ├── png.py               # PNG chunk parser & CRC validator
│   │   ├── pdf.py               # PDF xref/trailer validator
│   │   ├── zip.py               # ZIP/DOCX/XLSX archive parser
│   │   ├── mp4.py               # MP4 ISO atom parser
│   │   ├── mp3.py               # MP3 frame sync validator
│   │   └── sqlite.py            # SQLite page & PRAGMA check validator
│   ├── ml/
│   │   ├── features.py          # Statistical, entropy, and boundary feature extractors
│   │   ├── classifier.py        # AI Model 1: File type classifier
│   │   ├── embeddings.py        # AI Model 3: Fragment embedding & similarity
│   │   ├── relationship_model.py# AI Model 2: Successor prediction model
│   │   ├── clustering.py        # Multi-file fragment separation
│   │   └── ranking.py           # Sequence scoring engine
│   ├── security/
│   │   ├── hashing.py           # Streaming SHA-256 / MD5 hashing
│   │   └── audit.py             # Forensic chain-of-custody audit logger
│   ├── static/
│   │   └── index.html           # Full interactive Web UI dashboard
│   └── workers/
│       └── recovery_worker.py   # Asynchronous multi-stage job worker
├── training/
│   ├── generate_dataset.py      # Synthetic ground-truth corruption generator
│   ├── prepare_data.py          # Single and pair feature matrix builder
│   ├── extract_features.py      # Offline feature extraction batch script
│   ├── train_classifier.py      # Trains file classifier model
│   ├── train_relationship_model.py # Trains relationship transition model
│   └── evaluate.py              # Multi-metric evaluation and benchmark suite
├── frontend/                    # Standalone React + TypeScript + Tailwind UI
├── models/                      # Saved trained models (.joblib)
├── datasets/                    # Ground-truth synthetic training data
├── recovery_workspace/          # Sandboxed input/output/working directories
├── tests/
│   └── test_recovery.py         # 17 automated pytest test cases
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate Synthetic Dataset & Train AI Models
```bash
python -m training.generate_dataset
python -m training.train_classifier
python -m training.train_relationship_model
```

### 3. Run Benchmark Evaluation
```bash
python -m training.evaluate
```

### 4. Run Automated Test Suite
```bash
pytest tests/test_recovery.py -v
```

### 5. Launch FastAPI Backend & Interactive UI Dashboard
```bash
python -m backend.main
```
Open your browser to:
- **Web Dashboard**: `http://localhost:8000/`
- **Interactive Swagger API Docs**: `http://localhost:8000/docs`

---

## API Documentation

### Start Recovery Job
```http
POST /api/recovery/start
Content-Type: application/json

{
  "operation": "recover_corrupted",
  "source_type": "uploaded_file",
  "source_path": "datasets/originals/clean_photo.jpg",
  "target_type": "jpeg",
  "target_filename": "recovered_evidence.jpg"
}
```

Response:
```json
{
  "job_id": "REC-4A9B1C2D",
  "status": "created",
  "message": "Recovery job initialized and dispatched to background processing."
}
```

### Query Job Status & Progress
```http
GET /api/recovery/{job_id}/status
```

Response:
```json
{
  "job_id": "REC-4A9B1C2D",
  "operation": "recover_corrupted",
  "status": "completed",
  "current_stage": "completed",
  "progress": 100,
  "source": {
    "source_path": ".../clean_photo.jpg",
    "source_sha256": "3e7b1a...",
    "source_size": 10635,
    "filesystem_detected": "unknown",
    "is_read_only": true
  }
}
```

### Retrieve Results & Forensic Metrics
```http
GET /api/recovery/{job_id}/results
```

Response:
```json
{
  "job_id": "REC-4A9B1C2D",
  "status": "completed",
  "files_found": 1,
  "recoveries": [
    {
      "file_id": "REC_FILE_1",
      "filename": "recovered_evidence.jpg",
      "type": "jpeg",
      "fragments_used": ["frag_0000", "frag_0001", "frag_0002"],
      "fragments_missing": [],
      "model_confidence": 0.95,
      "recoverability_score": 100.0,
      "integrity_score": 100.0,
      "status": "fully_recoverable",
      "recovered_bytes": 10635,
      "missing_bytes": 0,
      "fabricated_bytes": 0,
      "validation": {
        "parser_success": true,
        "dimensions": [256, 256],
        "errors": [],
        "warnings": []
      },
      "output_path": ".../recovery_workspace/output/recovered_evidence.jpg"
    }
  ]
}
```

### Download Reconstructed File
```http
GET /api/recovery/{job_id}/download/{file_id}
```

### Download Forensic Audit Report
```http
GET /api/recovery/{job_id}/report?format=markdown
```

---

## Docker Deployment

To launch containerized:
```bash
docker-compose up --build
```
The recovery server and UI dashboard will be accessible at `http://localhost:8000/`.

"""
Binary Feature Extraction Engine for File Type Classification and Fragment Relationship Modeling.
Extracts measurable statistical, entropy, n-gram, and boundary transition features.
"""
import math
import numpy as np
from typing import Dict, Any, Tuple, List
from backend.recovery.fragments import Fragment
from backend.recovery.scanner import calculate_entropy

SUPPORTED_TYPES = ["jpeg", "png", "pdf", "zip", "mp4", "mp3", "sqlite", "unknown"]

def extract_single_fragment_features(data: bytes) -> np.ndarray:
    """
    Extract a comprehensive 270-dimensional feature vector from a byte slice.
    - 256-dim: Normalized byte histogram
    - 1-dim: Shannon entropy (0 to 8)
    - 1-dim: ASCII printable ratio
    - 1-dim: Null byte (0x00) ratio
    - 1-dim: Marker byte (0xFF) ratio
    - 1-dim: High byte (>=128) ratio
    - 1-dim: Mean byte value / 255
    - 1-dim: Byte variance / (255^2)
    - 8-dim: Magic byte presence indicators for known formats
    """
    if not data:
        return np.zeros(270, dtype=np.float32)
        
    length = len(data)
    hist = np.zeros(256, dtype=np.float32)
    for b in data:
        hist[b] += 1.0
    hist /= max(length, 1)
    
    entropy = calculate_entropy(data)
    ascii_count = sum(1 for b in data if (32 <= b <= 126) or b in (9, 10, 13))
    ascii_ratio = ascii_count / max(length, 1)
    null_ratio = hist[0]
    ff_ratio = hist[255]
    high_ratio = float(np.sum(hist[128:]))
    mean_val = float(np.mean(list(data))) / 255.0
    var_val = float(np.var(list(data))) / (255.0 ** 2)
    
    # Magic indicators in first 16 bytes
    prefix = data[:16]
    magic_indicators = np.zeros(8, dtype=np.float32)
    if b"\xFF\xD8\xFF" in prefix:
        magic_indicators[0] = 1.0 # JPEG
    if b"\x89PNG" in prefix:
        magic_indicators[1] = 1.0 # PNG
    if b"%PDF" in prefix:
        magic_indicators[2] = 1.0 # PDF
    if b"PK\x03\x04" in prefix:
        magic_indicators[3] = 1.0 # ZIP
    if b"ftyp" in prefix:
        magic_indicators[4] = 1.0 # MP4
    if b"ID3" in prefix:
        magic_indicators[5] = 1.0 # MP3
    if b"SQLite" in prefix:
        magic_indicators[6] = 1.0 # SQLite
    if b"\xFF\xD9" in data[-4:]:
        magic_indicators[7] = 1.0 # Has EOF/EOI marker
        
    stats = np.array([
        entropy / 8.0,
        ascii_ratio,
        null_ratio,
        ff_ratio,
        high_ratio,
        mean_val,
        var_val
    ], dtype=np.float32)
    
    return np.concatenate([hist, stats, magic_indicators])

def extract_pair_features(frag_a: Fragment, frag_b: Fragment) -> np.ndarray:
    """
    Extract pairwise relationship features between Fragment A and Fragment B.
    Evaluates:
      - How likely is Fragment B to be the immediate successor of Fragment A?
    Features include:
      1. Entropy continuity (abs delta)
      2. Histogram distance (Euclidean and L1)
      3. Boundary transition continuity (bigrams across tail of A and head of B)
      4. Offset delta and stride
      5. Header / Footer compatibility flags
      6. Type prediction compatibility
      7. Byte variance delta
    """
    feat_a = extract_single_fragment_features(frag_a.data)
    feat_b = extract_single_fragment_features(frag_b.data)
    
    # 1. Entropy difference
    entropy_diff = abs(frag_a.entropy - frag_b.entropy)
    
    # 2. Histogram differences
    hist_a = feat_a[:256]
    hist_b = feat_b[:256]
    hist_l1 = float(np.sum(np.abs(hist_a - hist_b)))
    hist_l2 = float(np.linalg.norm(hist_a - hist_b))
    
    # 3. Boundary byte patterns
    tail_a = frag_a.suffix_bytes[-8:] if len(frag_a.suffix_bytes) >= 8 else frag_a.data[-8:]
    head_b = frag_b.prefix_bytes[:8] if len(frag_b.prefix_bytes) >= 8 else frag_b.data[:8]
    
    boundary_cross_entropy = 0.0
    boundary_diff = 1.0
    if tail_a and head_b:
        boundary_slice = tail_a + head_b
        boundary_cross_entropy = calculate_entropy(boundary_slice) / 8.0
        boundary_diff = abs(float(tail_a[-1]) - float(head_b[0])) / 255.0
        
    # 4. Offset proximity
    offset_delta = frag_b.source_offset - (frag_a.source_offset + frag_a.length)
    is_contiguous = 1.0 if offset_delta == 0 else 0.0
    # Scaled proximity indicator (closer offsets are more likely from same file)
    offset_proximity = math.exp(-abs(offset_delta) / (64.0 * 1024.0)) if abs(offset_delta) < 10 * 1024 * 1024 else 0.0
    
    # 5. Logical role constraints
    # A cannot follow if A is footer; B cannot succeed if B is header
    invalid_role_penalty = 0.0
    if frag_a.is_footer:
        invalid_role_penalty += 1.0
    if frag_b.is_header:
        invalid_role_penalty += 1.0
        
    # 6. Type compatibility
    type_compat = 1.0 if frag_a.predicted_type == frag_b.predicted_type and frag_a.predicted_type != "unknown" else 0.5
    
    # 7. Format specific continuity checks
    # For JPEG: if tail of A ends with 0xFF, head of B must be valid marker or 0x00
    format_transition_valid = 1.0
    if frag_a.predicted_type == "jpeg" or frag_b.predicted_type == "jpeg":
        if tail_a and tail_a[-1] == 0xFF:
            if head_b and head_b[0] not in (0x00, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD9):
                format_transition_valid = 0.0 # Illegal byte after 0xFF in entropy-coded JPEG
                
    features = np.array([
        entropy_diff,
        hist_l1,
        hist_l2,
        boundary_cross_entropy,
        boundary_diff,
        is_contiguous,
        offset_proximity,
        invalid_role_penalty,
        type_compat,
        format_transition_valid,
        abs(feat_a[257] - feat_b[257]), # ASCII ratio diff
        abs(feat_a[258] - feat_b[258]), # Null ratio diff
        abs(feat_a[259] - feat_b[259])  # 0xFF ratio diff
    ], dtype=np.float32)
    
    return features

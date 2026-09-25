"""
Candidate Sequence Scoring and Ranking Engine.
Computes technical sequence scores incorporating relationship probabilities,
format consistency, parser results, and structural penalties.
"""
from typing import List, Dict, Any
from backend.recovery.fragments import Fragment

def calculate_sequence_score(
    sequence: List[Fragment],
    edge_probabilities: List[float],
    format_consistency: float,
    parser_consistency: float,
    metadata_consistency: float = 1.0,
    corruption_penalty: float = 0.0,
    missing_fragment_penalty: float = 0.0,
    duplicate_penalty: float = 0.0
) -> float:
    """
    Computes sequence score according to forensic objective function:
      sequence_score = (relationship_score * format_consistency * parser_consistency * metadata_consistency)
                       - corruption_penalty - missing_fragment_penalty - duplicate_penalty
    """
    if not sequence:
        return 0.0

    if edge_probabilities:
        avg_rel_score = sum(edge_probabilities) / len(edge_probabilities)
    else:
        avg_rel_score = 0.50

    base_score = avg_rel_score * format_consistency * parser_consistency * metadata_consistency
    total_penalties = corruption_penalty + missing_fragment_penalty + duplicate_penalty
    final_score = max(0.0, min(100.0, (base_score * 100.0) - (total_penalties * 100.0)))
    return round(final_score, 2)

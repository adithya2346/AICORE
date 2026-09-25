"""
Relationship Graph and Reconstruction Engine.
Constructs NetworkX directed graphs of fragment transitions, searches for candidate sequences,
scores paths using measurable evidence, and reconstructs files from real bytes.
Never invents or fabricates bytes.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import networkx as nx

from backend.recovery.fragments import Fragment
from backend.ml.relationship_model import relationship_model
from backend.ml.ranking import calculate_sequence_score
from backend.formats import get_format_plugin, detect_format_plugin
from backend.formats.base import FormatPlugin, ValidationResult

@dataclass
class ReconstructionCandidate:
    candidate_id: str
    rank: int
    fragment_sequence: List[str] # Fragment IDs
    fragments: List[Fragment]
    reconstructed_bytes: bytes
    sequence_score: float # 0 to 100
    avg_relationship_probability: float
    validation_result: ValidationResult
    is_selected: bool = False
    evidence: List[str] = field(default_factory=list)

class ReconstructionEngine:
    """
    Solves fragment ordering using relationship graphs, beam search, and format-specific validators.
    """
    def __init__(self, target_type: Optional[str] = None):
        self.target_type = target_type
        self.plugin: Optional[FormatPlugin] = get_format_plugin(target_type) if target_type else None

    def build_relationship_graph(self, fragments: List[Fragment]) -> nx.DiGraph:
        """
        Builds directed transition graph over candidate fragments.
        Each edge has attributes:
          - probability: ML & heuristic successor probability
          - relationship_type: 'likely_successor', 'possible_successor', etc.
          - evidence: dictionary of technical features
        """
        G = nx.DiGraph()
        for f in fragments:
            G.add_node(
                f.fragment_id,
                fragment=f,
                is_header=f.is_header,
                is_footer=f.is_footer,
                entropy=f.entropy,
                type=f.predicted_type
            )

        n = len(fragments)
        for i in range(n):
            frag_a = fragments[i]
            for j in range(n):
                if i == j:
                    continue
                frag_b = fragments[j]
                prob, rel_type, evidence = relationship_model.predict_successor(frag_a, frag_b)
                
                # Check format plugin boundary compatibility if available
                if self.plugin:
                    boundary_score = self.plugin.check_boundary(frag_a, frag_b)
                    prob = (prob * 0.70) + (boundary_score * 0.30)
                    evidence["format_boundary_score"] = round(boundary_score, 3)

                if prob >= 0.15: # Prune improbable transitions
                    G.add_edge(
                        frag_a.fragment_id,
                        frag_b.fragment_id,
                        weight=prob,
                        probability=prob,
                        relationship_type=rel_type,
                        evidence=evidence
                    )

        return G

    def find_candidate_sequences(
        self,
        fragments: List[Fragment],
        max_candidates: int = 5,
        beam_width: int = 4
    ) -> List[List[Fragment]]:
        """
        Performs beam search heuristic on the relationship graph to find best sequence orderings.
        """
        if not fragments:
            return []
        if len(fragments) == 1:
            return [fragments]

        frag_map = {f.fragment_id: f for f in fragments}
        G = self.build_relationship_graph(fragments)

        # 1. Identify start candidates (headers or nodes with highest net outgoing probability)
        headers = [f for f in fragments if f.is_header]
        if not headers:
            # Sort by predicted format header or lowest source offset
            headers = sorted(fragments, key=lambda f: (not f.is_header, f.source_offset))

        start_nodes = [h.fragment_id for h in headers[:3]]
        
        # Beam search: each state is (cumulative_score, [frag_ids], visited_set)
        beams = []
        for s_id in start_nodes:
            beams.append((0.0, [s_id], {s_id}))

        target_length = len(fragments)
        for step in range(target_length - 1):
            next_beams = []
            for score, path, visited in beams:
                last_node = path[-1]
                # Look at outgoing edges from last_node
                neighbors = []
                for nbr in G.successors(last_node):
                    if nbr not in visited:
                        edge_data = G.get_edge_data(last_node, nbr)
                        prob = edge_data.get("probability", 0.5)
                        neighbors.append((nbr, prob))

                if not neighbors:
                    # If dead-end in graph, fallback to remaining unvisited nodes
                    unvisited = [f_id for f_id in frag_map if f_id not in visited]
                    for uv in unvisited[:3]:
                        neighbors.append((uv, 0.20))

                for nbr, prob in neighbors:
                    new_score = score + prob
                    new_path = path + [nbr]
                    new_visited = visited | {nbr}
                    next_beams.append((new_score, new_path, new_visited))

            if not next_beams:
                break
                
            # Keep top beam_width paths
            next_beams.sort(key=lambda item: item[0], reverse=True)
            beams = next_beams[:beam_width]

        # Extract sequence candidates
        candidate_sequences = []
        seen_seqs = set()
        
        for score, path, visited in beams:
            # Append any remaining disconnected fragments if beam missed them
            missing = [f_id for f_id in frag_map if f_id not in visited]
            full_path = path + missing
            path_key = tuple(full_path)
            if path_key not in seen_seqs:
                seen_seqs.add(path_key)
                frag_objs = [frag_map[fid] for fid in full_path]
                candidate_sequences.append(frag_objs)

        return candidate_sequences[:max_candidates]

    def reconstruct_and_evaluate(self, fragments: List[Fragment], max_candidates: int = 5) -> List[ReconstructionCandidate]:
        """
        Executes sequence generation, byte assembly, and format validation.
        Selects the best sequence while preserving alternative candidates.
        """
        if not fragments:
            return []

        # Autodetect format plugin if none specified
        if not self.plugin:
            first_data = fragments[0].data if fragments else b""
            self.plugin = detect_format_plugin(first_data)

        if len(fragments) == 1:
            sequences = [[fragments[0]]]
        else:
            eval_frags = fragments[:20] if len(fragments) > 20 else fragments
            sequences = self.find_candidate_sequences(eval_frags, max_candidates=max_candidates)
        reconstruction_candidates: List[ReconstructionCandidate] = []

        for idx, seq in enumerate(sequences):
            # Assemble actual bytes from fragment sequence
            reconstructed_data = b"".join(f.data for f in seq)
            
            # Format validation
            val_result = (
                self.plugin.validate(reconstructed_data)
                if self.plugin
                else ValidationResult(
                    is_valid=True,
                    decoder_success=True,
                    file_size=len(reconstructed_data),
                    structural_score=50.0
                )
            )

            # Edge relationship probabilities
            edge_probs = []
            for i in range(len(seq) - 1):
                prob, _, _ = relationship_model.predict_successor(seq[i], seq[i + 1])
                edge_probs.append(prob)

            format_consistency = val_result.structural_score / 100.0
            parser_consistency = 1.0 if val_result.decoder_success else 0.50

            score = calculate_sequence_score(
                sequence=seq,
                edge_probabilities=edge_probs,
                format_consistency=format_consistency,
                parser_consistency=parser_consistency
            )

            evidence_items = [
                f"Assembled {len(seq)} fragments ({len(reconstructed_data)} bytes)",
                f"Format structural consistency: {val_result.structural_score:.1f}%",
                f"Parser status: {'PASSED' if val_result.decoder_success else 'FAILED'}"
            ]
            if val_result.dimensions:
                evidence_items.append(f"Decoded dimensions: {val_result.dimensions[0]}x{val_result.dimensions[1]}")

            cand = ReconstructionCandidate(
                candidate_id=f"CAND_{idx + 1:03d}",
                rank=idx + 1,
                fragment_sequence=[f.fragment_id for f in seq],
                fragments=seq,
                reconstructed_bytes=reconstructed_data,
                sequence_score=score,
                avg_relationship_probability=round(sum(edge_probs) / max(len(edge_probs), 1), 3),
                validation_result=val_result,
                is_selected=(idx == 0),
                evidence=evidence_items
            )
            reconstruction_candidates.append(cand)

        # Sort candidates by sequence score descending
        reconstruction_candidates.sort(key=lambda c: c.sequence_score, reverse=True)
        for i, c in enumerate(reconstruction_candidates):
            c.rank = i + 1
            c.is_selected = (i == 0)

        return reconstruction_candidates

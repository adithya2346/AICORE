export interface SourceInfo {
  source_path: string;
  source_sha256: string;
  source_size: number;
  source_type: string;
  sector_size: number;
  filesystem_detected: string;
  is_read_only: boolean;
  acquired_at?: string;
}

export interface FragmentInfo {
  fragment_id: string;
  offset: number;
  length: number;
  sha256: string;
  predicted_type: string;
  entropy: number;
  is_header: boolean;
  is_footer: boolean;
  status: string;
}

export interface RelationshipInfo {
  from_fragment: string;
  to_fragment: string;
  probability: number;
  type: string;
}

export interface CandidateInfo {
  rank: number;
  score: number;
  parser_valid: boolean;
  sequence: string[];
}

export interface MissingRegion {
  estimated_offset: number;
  estimated_size: number;
  status: string;
  description: string;
}

export interface RecoveredFileInfo {
  file_id: string;
  filename: string;
  type: string;
  fragments_used: string[];
  fragments_missing: MissingRegion[];
  model_confidence: number;
  recoverability_score: number;
  integrity_score: number;
  status: string;
  recovered_bytes: number;
  missing_bytes: number;
  fabricated_bytes: number;
  validation: {
    parser_success: boolean;
    dimensions?: [number, number];
    errors: string[];
    warnings: string[];
  };
  output_path: string;
}

export interface RecoveryJobStatus {
  job_id: string;
  operation: string;
  status: string;
  current_stage: string;
  progress: number;
  error?: string;
  source?: SourceInfo;
  created_at: string;
  updated_at: string;
}

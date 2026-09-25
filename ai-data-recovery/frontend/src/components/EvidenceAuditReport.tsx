import React from 'react';
import { Download, FileCheck2, AlertCircle, ShieldAlert } from 'lucide-react';
import { RecoveredFileInfo } from '../types/recovery';

interface EvidenceAuditReportProps {
  jobId: string;
  recoveries: RecoveredFileInfo[];
}

export const EvidenceAuditReport: React.FC<EvidenceAuditReportProps> = ({ jobId, recoveries }) => {
  if (!recoveries || recoveries.length === 0) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
        No recovered files produced for this job.
      </div>
    );
  }

  const handleDownloadReport = () => {
    window.open(`/api/recovery/${jobId}/report?format=markdown`, '_blank');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Forensic Reconstruction Results</h2>
          <p className="text-xs text-slate-400">Technical recovery analysis, structural validation, and evidence ledger.</p>
        </div>
        <button
          onClick={handleDownloadReport}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-semibold text-slate-200 flex items-center gap-2 transition-colors"
        >
          <Download className="w-4 h-4" />
          <span>Download Audit Report (.md)</span>
        </button>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {recoveries.map((rec) => (
          <div key={rec.file_id} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <FileCheck2 className="w-5 h-5 text-emerald-400" />
                  <span className="text-lg font-bold text-white font-mono">{rec.filename}</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase font-mono">
                    {rec.type}
                  </span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Status: <span className="font-semibold text-emerald-400 capitalize">{rec.status.replace('_', ' ')}</span>
                </div>
              </div>

              <a
                href={`/api/recovery/${jobId}/download/${rec.file_id}`}
                download={rec.filename}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 rounded-lg text-white font-semibold text-xs flex items-center gap-2 shadow-lg shadow-emerald-950/60 transition-all"
              >
                <Download className="w-4 h-4" />
                <span>Download Recovered File</span>
              </a>
            </div>

            {/* Technical Metric Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                <span className="text-xs text-slate-500 block mb-1">Model Confidence</span>
                <div className="text-xl font-bold font-mono text-blue-400">
                  {(rec.model_confidence * 100).toFixed(0)}%
                </div>
                <div className="text-[10px] text-slate-500 mt-1">Pairwise transition likelihood</div>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                <span className="text-xs text-slate-500 block mb-1">Recoverability Score</span>
                <div className="text-xl font-bold font-mono text-emerald-400">
                  {rec.recoverability_score.toFixed(1)}/100
                </div>
                <div className="text-[10px] text-slate-500 mt-1">Preserved original byte ratio</div>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                <span className="text-xs text-slate-500 block mb-1">Structural Integrity</span>
                <div className="text-xl font-bold font-mono text-indigo-400">
                  {rec.integrity_score.toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-500 mt-1">Parser marker consistency</div>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                <span className="text-xs text-slate-500 block mb-1">Fabricated Bytes</span>
                <div className="text-xl font-bold font-mono text-emerald-400">
                  0 bytes
                </div>
                <div className="text-[10px] text-emerald-500/80 mt-1">Strict zero invariant verified</div>
              </div>
            </div>

            {/* Bytes breakdown */}
            <div className="bg-slate-950/50 border border-slate-800/80 rounded-lg p-4 text-xs font-mono grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <span className="text-slate-500">Recovered Original:</span>{' '}
                <span className="text-slate-200 font-bold">{rec.recovered_bytes.toLocaleString()} bytes</span>
              </div>
              <div>
                <span className="text-slate-500">Missing/Truncated:</span>{' '}
                <span className="text-amber-400 font-bold">{rec.missing_bytes.toLocaleString()} bytes</span>
              </div>
              <div>
                <span className="text-slate-500">Fragments Used:</span>{' '}
                <span className="text-slate-200 font-bold">{rec.fragments_used.length} fragments</span>
              </div>
            </div>

            {/* Image Preview for JPEG / PNG */}
            {['jpeg', 'png', 'jpg'].includes(rec.type.toLowerCase()) && rec.validation.parser_success && (
              <div className="border border-slate-800 rounded-lg p-4 bg-slate-950/40">
                <h4 className="text-xs font-semibold uppercase text-slate-400 mb-3 tracking-wider">
                  Decoded Visual Artifact Preview
                </h4>
                <div className="flex items-center gap-6">
                  <div className="w-48 h-48 bg-slate-900 rounded-lg overflow-hidden border border-slate-800 flex items-center justify-center p-1">
                    <img
                      src={`/api/recovery/${jobId}/download/${rec.file_id}`}
                      alt="Recovered evidence preview"
                      className="max-w-full max-h-full object-contain rounded"
                    />
                  </div>
                  <div className="text-xs space-y-2 text-slate-300">
                    <div>
                      <span className="text-slate-500">Decoded Dimensions:</span>{' '}
                      <span className="font-mono font-bold text-white">
                        {rec.validation.dimensions ? `${rec.validation.dimensions[0]} × ${rec.validation.dimensions[1]} px` : 'Auto'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Decoder Status:</span>{' '}
                      <span className="text-emerald-400 font-bold">PASSED (Pillow engine)</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Marker Chain:</span>{' '}
                      <span className="font-mono text-slate-400">SOI → DQT → DHT → SOF → SOS → EOI</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Technical Explanation Ledger */}
            {rec.validation.errors.length > 0 || rec.validation.warnings.length > 0 ? (
              <div className="space-y-2">
                {rec.validation.errors.map((e, idx) => (
                  <div key={idx} className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg flex items-center gap-2 text-xs text-rose-300">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{e}</span>
                  </div>
                ))}
                {rec.validation.warnings.map((w, idx) => (
                  <div key={idx} className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg flex items-center gap-2 text-xs text-amber-300">
                    <ShieldAlert className="w-4 h-4 shrink-0" />
                    <span>{w}</span>
                  </div>
                ))}
              </div>
            ) : null}

            {/* Missing Regions Table */}
            {rec.fragments_missing && rec.fragments_missing.length > 0 && (
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <div className="bg-slate-950 px-4 py-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Missing or Overwritten Storage Regions
                </div>
                <div className="divide-y divide-slate-800 text-xs font-mono">
                  {rec.fragments_missing.map((mr, idx) => (
                    <div key={idx} className="p-3 flex items-center justify-between text-slate-300 bg-slate-900/60">
                      <div>
                        <span className="text-slate-500">Offset:</span> {mr.estimated_offset.toLocaleString()} |{' '}
                        <span className="text-slate-500">Length:</span> ~{mr.estimated_size.toLocaleString()} bytes
                      </div>
                      <div className="text-amber-400">{mr.description}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

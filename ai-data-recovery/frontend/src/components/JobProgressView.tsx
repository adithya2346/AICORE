import React from 'react';
import { ShieldCheck, HardDrive, Cpu, AlertTriangle, CheckCircle2, Clock, XOctagon } from 'lucide-react';
import { RecoveryJobStatus } from '../types/recovery';

interface JobProgressViewProps {
  status: RecoveryJobStatus;
  onCancel: () => void;
}

const STAGES = [
  { id: 'created', label: 'Initialized' },
  { id: 'acquiring', label: 'Acquiring Evidence' },
  { id: 'hashing', label: 'Cryptographic Hashing' },
  { id: 'filesystem_analysis', label: 'Filesystem Parser' },
  { id: 'scanning', label: 'Raw Sector Scanning' },
  { id: 'carving', label: 'Signature Carving' },
  { id: 'fragment_analysis', label: 'AI Classification' },
  { id: 'relationship_analysis', label: 'Relationship Graph' },
  { id: 'reconstructing', label: 'Sequence Assembly' },
  { id: 'validating', label: 'Decoder Validation' },
  { id: 'completed', label: 'Completed' }
];

export const JobProgressView: React.FC<JobProgressViewProps> = ({ status, onCancel }) => {
  const isTerminated = ['completed', 'failed', 'cancelled'].includes(status.status);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs uppercase font-mono text-slate-400">Job Reference</span>
            <span className="text-sm font-mono font-bold text-blue-400 bg-blue-950/60 px-2 py-0.5 rounded border border-blue-800/60">
              {status.job_id}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded font-medium ${
              status.status === 'completed' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
              status.status === 'failed' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
              status.status === 'cancelled' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
              'bg-indigo-950 text-indigo-300 border border-indigo-800 animate-pulse'
            }`}>
              {status.status.toUpperCase()}
            </span>
          </div>
          <h3 className="text-lg font-bold text-white mt-1">Operation: {status.operation}</h3>
        </div>

        {!isTerminated && (
          <button
            onClick={onCancel}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-200 text-xs font-medium transition-colors"
          >
            <XOctagon className="w-4 h-4" />
            <span>Cancel Recovery</span>
          </button>
        )}
      </div>

      {/* Progress Bar */}
      <div>
        <div className="flex justify-between items-center text-xs mb-2">
          <span className="font-semibold text-slate-300 capitalize flex items-center gap-1.5">
            <Cpu className="w-4 h-4 text-blue-400" />
            Stage: {status.current_stage.replace('_', ' ')}
          </span>
          <span className="font-mono font-bold text-blue-400">{status.progress}%</span>
        </div>
        <div className="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
          <div
            className="h-full bg-gradient-to-r from-blue-600 via-indigo-500 to-emerald-400 transition-all duration-300"
            style={{ width: `${status.progress}%` }}
          />
        </div>
      </div>

      {/* Pipeline Stage Pills */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
        {STAGES.map((s, idx) => {
          const isDone = status.progress >= ((idx + 1) / STAGES.length) * 100 || status.status === 'completed';
          const isCurrent = status.current_stage === s.id;
          return (
            <div
              key={s.id}
              className={`p-2 rounded border text-xs text-center transition-colors ${
                isCurrent
                  ? 'bg-blue-900/40 border-blue-500 text-blue-200 font-bold'
                  : isDone
                  ? 'bg-slate-950 border-emerald-900/60 text-emerald-400'
                  : 'bg-slate-950/60 border-slate-800 text-slate-500'
              }`}
            >
              {s.label}
            </div>
          );
        })}
      </div>

      {/* Evidence Source Metadata Card */}
      {status.source && (
        <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div>
            <span className="text-slate-500 block mb-1">Source SHA-256</span>
            <span className="text-slate-300 font-bold break-all" title={status.source.source_sha256}>
              {status.source.source_sha256.slice(0, 16)}...{status.source.source_sha256.slice(-8)}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block mb-1">Evidence Size</span>
            <span className="text-slate-300">{(status.source.source_size / 1024).toFixed(1)} KB ({status.source.source_size.toLocaleString()} bytes)</span>
          </div>
          <div>
            <span className="text-slate-500 block mb-1">Filesystem</span>
            <span className="text-slate-300 uppercase">{status.source.filesystem_detected || 'Raw Stream'}</span>
          </div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <div>
              <span className="text-slate-500 block">Forensic Integrity</span>
              <span className="text-emerald-400 font-bold">READ-ONLY VERIFIED</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

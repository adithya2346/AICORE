import React from 'react';
import { GitBranch, CheckCircle2, XCircle } from 'lucide-react';
import { CandidateInfo } from '../types/recovery';

interface CandidateSequenceTableProps {
  candidates: CandidateInfo[];
}

export const CandidateSequenceTable: React.FC<CandidateSequenceTableProps> = ({ candidates }) => {
  if (!candidates || candidates.length === 0) return null;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <GitBranch className="w-5 h-5 text-blue-400" />
        <h3 className="text-lg font-bold text-white">Reconstruction Path Candidates</h3>
        <span className="text-xs text-slate-400 ml-auto">Preserved candidate sequences</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider">
            <tr>
              <th className="p-3">Rank</th>
              <th className="p-3">Sequence Path</th>
              <th className="p-3">Score</th>
              <th className="p-3">Parser Valid</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 text-slate-300">
            {candidates.map((c) => (
              <tr key={c.rank} className={c.rank === 1 ? 'bg-blue-950/20 font-bold text-white' : ''}>
                <td className="p-3">
                  <span className={`px-2 py-0.5 rounded ${c.rank === 1 ? 'bg-blue-500 text-white' : 'bg-slate-800 text-slate-400'}`}>
                    #{c.rank}
                  </span>
                </td>
                <td className="p-3 max-w-md truncate">
                  {c.sequence.join(' → ')}
                </td>
                <td className="p-3 text-emerald-400 font-bold">
                  {c.score.toFixed(1)}/100
                </td>
                <td className="p-3">
                  {c.parser_valid ? (
                    <span className="flex items-center gap-1 text-emerald-400">
                      <CheckCircle2 className="w-4 h-4" /> PASSED
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-rose-400">
                      <XCircle className="w-4 h-4" /> FAILED
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

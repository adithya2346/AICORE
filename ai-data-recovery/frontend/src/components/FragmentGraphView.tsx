import React from 'react';
import { Network, Activity, ArrowRight, Layers } from 'lucide-react';
import { FragmentInfo, RelationshipInfo } from '../types/recovery';

interface FragmentGraphViewProps {
  fragments: FragmentInfo[];
  relationships: RelationshipInfo[];
}

export const FragmentGraphView: React.FC<FragmentGraphViewProps> = ({ fragments, relationships }) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Network className="w-5 h-5 text-indigo-400" />
            Fragment Topology & Relationship Graph
          </h3>
          <p className="text-xs text-slate-400">
            {fragments.length} fragments analyzed with {relationships.length} high-confidence transition edges.
          </p>
        </div>
      </div>

      {/* Discovered Fragments Strip */}
      <div>
        <h4 className="text-xs font-semibold uppercase text-slate-400 mb-3 tracking-wider flex items-center gap-1.5">
          <Layers className="w-4 h-4 text-blue-400" />
          Discovered Binary Fragments
        </h4>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {fragments.map((f) => (
            <div
              key={f.fragment_id}
              className={`p-3 rounded-lg border text-xs font-mono transition-all ${
                f.is_header
                  ? 'bg-blue-950/40 border-blue-600/80 text-blue-200'
                  : f.is_footer
                  ? 'bg-purple-950/40 border-purple-600/80 text-purple-200'
                  : 'bg-slate-950/80 border-slate-800 text-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-bold">{f.fragment_id}</span>
                {f.is_header && <span className="text-[10px] bg-blue-500/20 px-1 rounded text-blue-300">HDR</span>}
                {f.is_footer && <span className="text-[10px] bg-purple-500/20 px-1 rounded text-purple-300">FTR</span>}
              </div>
              <div className="text-[11px] text-slate-500">Offset: {f.offset}</div>
              <div className="text-[11px] text-slate-500">Size: {f.length} B</div>
              <div className="mt-2 flex items-center justify-between text-[11px]">
                <span className="text-slate-400 uppercase">{f.predicted_type}</span>
                <span className="text-emerald-400">H: {f.entropy}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Primary Transition Edges */}
      {relationships.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase text-slate-400 mb-3 tracking-wider flex items-center gap-1.5">
            <Activity className="w-4 h-4 text-emerald-400" />
            Top Predicted Fragment Successor Transitions
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {relationships.slice(0, 9).map((r, idx) => (
              <div
                key={idx}
                className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between text-xs font-mono"
              >
                <div className="flex items-center gap-2">
                  <span className="text-blue-300">{r.from_fragment}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                  <span className="text-indigo-300">{r.to_fragment}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-slate-500">{r.type}</span>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-950 border border-emerald-800/60 text-emerald-400 font-bold">
                    {(r.probability * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { Shield, Layers, Sparkles } from 'lucide-react';
import { RecoveryWizard } from './components/RecoveryWizard';
import { JobProgressView } from './components/JobProgressView';
import { EvidenceAuditReport } from './components/EvidenceAuditReport';
import { FragmentGraphView } from './components/FragmentGraphView';
import { CandidateSequenceTable } from './components/CandidateSequenceTable';
import { AIRecoveryResultView } from './components/AIRecoveryResultView';
import { RecoveryJobStatus, RecoveredFileInfo, FragmentInfo, RelationshipInfo, CandidateInfo } from './types/recovery';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'ai_image' | 'disk_carving'>('ai_image');
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<RecoveryJobStatus | null>(null);
  const [recoveries, setRecoveries] = useState<RecoveredFileInfo[]>([]);
  const [candidates, setCandidates] = useState<CandidateInfo[]>([]);
  const [fragments, setFragments] = useState<FragmentInfo[]>([]);
  const [relationships, setRelationships] = useState<RelationshipInfo[]>([]);
  const [recentJobs, setRecentJobs] = useState<any[]>([]);

  // Fetch recent jobs
  const fetchRecentJobs = async () => {
    try {
      const res = await fetch('/api/recovery/jobs');
      if (res.ok) {
        const data = await res.json();
        setRecentJobs(data);
      }
    } catch (e) {
      // ignore
    }
  };

  useEffect(() => {
    fetchRecentJobs();
  }, []);

  // Poll active job status
  useEffect(() => {
    if (!activeJobId) return;

    let intervalId: any;

    const poll = async () => {
      try {
        const res = await fetch(`/api/recovery/${activeJobId}/status`);
        if (res.ok) {
          const data: RecoveryJobStatus = await res.json();
          setJobStatus(data);

          // If stage progressed or completed, fetch fragments and results
          if (['fragment_analysis', 'relationship_analysis', 'reconstructing', 'validating', 'completed'].includes(data.current_stage) || data.status === 'completed') {
            const fRes = await fetch(`/api/recovery/${activeJobId}/fragments`);
            if (fRes.ok) {
              const fData = await fRes.json();
              setFragments(fData.fragments || []);
              setRelationships(fData.relationships || []);
            }
          }

          if (data.status === 'completed') {
            const rRes = await fetch(`/api/recovery/${activeJobId}/results`);
            if (rRes.ok) {
              const rData = await rRes.json();
              setRecoveries(rData.recoveries || []);
              setCandidates(rData.reconstruction_candidates || []);
            }
            clearInterval(intervalId);
            fetchRecentJobs();
          } else if (['failed', 'cancelled'].includes(data.status)) {
            clearInterval(intervalId);
            fetchRecentJobs();
          }
        }
      } catch (err) {
        console.error(err);
      }
    };

    poll();
    intervalId = setInterval(poll, 1500);

    return () => clearInterval(intervalId);
  }, [activeJobId]);

  const handleCancel = async () => {
    if (!activeJobId) return;
    try {
      await fetch(`/api/recovery/cancel/${activeJobId}`, { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between shadow-md">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center shadow-lg shadow-blue-900/50">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white tracking-wide">
              AI Forensic Data Recovery & Evidence Reconstruction
            </h1>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span className="flex items-center gap-1 text-emerald-400">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block animate-ping" />
                Read-Only Engine
              </span>
              <span>•</span>
              <span>FastAPI Backend</span>
              <span>•</span>
              <span>Zero Hallucination / 0 Fabricated Bytes</span>
            </div>
          </div>
        </div>

        {recentJobs.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Recent Jobs:</span>
            <select
              value={activeJobId || ''}
              onChange={(e) => setActiveJobId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
            >
              <option value="">Select past job</option>
              {recentJobs.map((j) => (
                <option key={j.job_id} value={j.job_id}>
                  {j.job_id} - {j.status.toUpperCase()} ({j.operation})
                </option>
              ))}
            </select>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <button
            onClick={() => setActiveTab('ai_image')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'ai_image'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-900/30'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <Sparkles className="w-4 h-4" />
            AI-Assisted Image Recovery
          </button>

          <button
            onClick={() => setActiveTab('disk_carving')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'disk_carving'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/30'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            <Layers className="w-4 h-4" />
            Forensic Disk & Evidence Carving
          </button>
        </div>

        {activeTab === 'ai_image' ? (
          <AIRecoveryResultView />
        ) : (
          <>
            {/* New Job Setup */}
            <RecoveryWizard onJobStarted={(id) => setActiveJobId(id)} />

            {/* Active Job Progress View */}
            {jobStatus && (
              <JobProgressView status={jobStatus} onCancel={handleCancel} />
            )}

            {/* Fragment Graph and Topology */}
            {fragments.length > 0 && (
              <FragmentGraphView fragments={fragments} relationships={relationships} />
            )}

            {/* Alternative Candidate Sequence Table */}
            {candidates.length > 0 && (
              <CandidateSequenceTable candidates={candidates} />
            )}

            {/* Reconstructed Evidence Audit Report */}
            {activeJobId && (
              <EvidenceAuditReport jobId={activeJobId} recoveries={recoveries} />
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-4 text-center text-xs text-slate-600">
        Forensic Binary Analysis & Neural Relationship Reconstruction Platform • Strictly Preserving Digital Evidence
      </footer>
    </div>
  );
};

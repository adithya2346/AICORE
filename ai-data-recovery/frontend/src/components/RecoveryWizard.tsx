import React, { useState } from 'react';
import { Shield, Upload, FileText, HardDrive, Play, AlertCircle } from 'lucide-react';

interface RecoveryWizardProps {
  onJobStarted: (jobId: string) => void;
}

export const RecoveryWizard: React.FC<RecoveryWizardProps> = ({ onJobStarted }) => {
  const [operation, setOperation] = useState<'recover_corrupted' | 'recover_deleted'>('recover_corrupted');
  const [sourceType, setSourceType] = useState<'uploaded_file' | 'disk_image'>('uploaded_file');
  const [sourcePath, setSourcePath] = useState('');
  const [targetFilename, setTargetFilename] = useState('');
  const [targetType, setTargetType] = useState('jpeg');
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setError(null);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('operation', operation);
    if (targetType) formData.append('target_type', targetType);

    try {
      const res = await fetch('/api/recovery/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (res.ok) {
        setSourcePath(data.source_path);
        if (!targetFilename) {
          setTargetFilename(`recovered_${file.name}`);
        }
      } else {
        setError(data.detail || 'Upload failed');
      }
    } catch (err: any) {
      setError(err.message || 'Network error during upload');
    } finally {
      setUploading(false);
    }
  };

  const handleStart = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sourcePath) {
      setError('Please provide or upload an authorized evidence source.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/recovery/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation,
          source_type: sourceType,
          source_path: sourcePath,
          target_filename: targetFilename || undefined,
          target_type: targetType || undefined
        })
      });

      const data = await res.json();
      if (res.ok) {
        onJobStarted(data.job_id);
      } else {
        setError(data.detail || 'Failed to start recovery job');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to connect to recovery engine');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl">
      <div className="flex items-center gap-3 mb-6 border-b border-slate-800 pb-4">
        <Shield className="w-6 h-6 text-emerald-400" />
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide">Authorized Evidence Acquisition & Analysis</h2>
          <p className="text-xs text-slate-400">Strictly read-only binary parsing. No hallucination or byte fabrication.</p>
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-rose-950/60 border border-rose-800/80 rounded-lg flex items-center gap-3 text-rose-300 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleStart} className="space-y-6">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Recovery Mode
          </label>
          <div className="grid grid-cols-2 gap-4">
            <button
              type="button"
              onClick={() => {
                setOperation('recover_corrupted');
                setSourceType('uploaded_file');
              }}
              className={`p-4 rounded-lg border text-left flex items-start gap-3 transition-all ${
                operation === 'recover_corrupted'
                  ? 'bg-blue-950/40 border-blue-500/80 text-white shadow-lg shadow-blue-950/50'
                  : 'bg-slate-800/40 border-slate-700/60 text-slate-400 hover:border-slate-600'
              }`}
            >
              <FileText className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-sm">Mode A: Damaged File Recovery</div>
                <div className="text-xs text-slate-400 mt-1">Carve valid fragments, reassemble sequences, repair corrupted sections.</div>
              </div>
            </button>

            <button
              type="button"
              onClick={() => {
                setOperation('recover_deleted');
                setSourceType('disk_image');
              }}
              className={`p-4 rounded-lg border text-left flex items-start gap-3 transition-all ${
                operation === 'recover_deleted'
                  ? 'bg-purple-950/40 border-purple-500/80 text-white shadow-lg shadow-purple-950/50'
                  : 'bg-slate-800/40 border-slate-700/60 text-slate-400 hover:border-slate-600'
              }`}
            >
              <HardDrive className="w-5 h-5 text-purple-400 shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-sm">Mode B: Deleted File / Disk Image</div>
                <div className="text-xs text-slate-400 mt-1">NTFS/FAT/exFAT metadata analysis and unallocated raw carving.</div>
              </div>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
              Upload Damaged File or Disk Image
            </label>
            <div className="relative border-2 border-dashed border-slate-700 rounded-lg p-6 hover:border-slate-500 transition-colors text-center bg-slate-950/40">
              <input
                type="file"
                onChange={handleFileUpload}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                disabled={uploading}
              />
              <Upload className="w-8 h-8 mx-auto mb-2 text-slate-400" />
              <div className="text-sm font-medium text-slate-300">
                {uploading ? 'Uploading to secure sandbox...' : 'Drop file here or click to browse'}
              </div>
              <div className="text-xs text-slate-500 mt-1">Accepts images, raw binaries, .dd, .img</div>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Authorized Evidence Source Path
              </label>
              <input
                type="text"
                value={sourcePath}
                onChange={(e) => setSourcePath(e.target.value)}
                placeholder="e.g. /recovery/input/corrupted.bin or D:/image.dd"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                  Target Format
                </label>
                <select
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="jpeg">JPEG Image</option>
                  <option value="png">PNG Image</option>
                  <option value="pdf">PDF Document</option>
                  <option value="zip">ZIP / DOCX Archive</option>
                  <option value="mp4">MP4 Video</option>
                  <option value="mp3">MP3 Audio</option>
                  <option value="sqlite">SQLite Database</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                  Output Filename
                </label>
                <input
                  type="text"
                  value={targetFilename}
                  onChange={(e) => setTargetFilename(e.target.value)}
                  placeholder="e.g. college_event.jpg"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || uploading}
          className="w-full py-3 px-6 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold flex items-center justify-center gap-2 shadow-lg shadow-blue-900/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Play className="w-4 h-4 fill-current" />
          <span>{loading ? 'Initializing Recovery...' : 'Start Forensic Recovery'}</span>
        </button>
      </form>
    </div>
  );
};

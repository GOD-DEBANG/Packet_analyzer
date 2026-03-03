import { useState, useRef } from 'react';
import {
  Upload, FileText, Zap, X, CheckCircle, AlertCircle,
  Shield, Wifi, Globe, ChevronDown, ChevronUp
} from 'lucide-react';
import {
  mockStats, mockAppBreakdown, mockFlows, defaultBlockedApps,
  defaultBlockedIPs, defaultBlockedDomains, formatBytes, allApps
} from '../data/mockAnalysis';

const STAGES = [
  { id: 1, label: 'Reading PCAP file',        duration: 400 },
  { id: 2, label: 'Parsing protocol headers', duration: 500 },
  { id: 3, label: 'Extracting SNI / HTTP hosts', duration: 600 },
  { id: 4, label: 'Classifying applications', duration: 450 },
  { id: 5, label: 'Applying blocking rules',  duration: 350 },
  { id: 6, label: 'Generating output report', duration: 300 },
];

export default function Analyzer() {
  const [file, setFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [running, setRunning] = useState(false);
  const [stage, setStage] = useState(-1);
  const [done, setDone] = useState(false);
  const [results, setResults] = useState(null);
  const [blockedApps, setBlockedApps] = useState(defaultBlockedApps);
  const [blockedIPs, setBlockedIPs] = useState(defaultBlockedIPs);
  const [blockedDomains, setBlockedDomains] = useState(defaultBlockedDomains);
  const [ipInput, setIpInput] = useState('');
  const [domInput, setDomInput] = useState('');
  const [showRules, setShowRules] = useState(true);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const fileInputRef = useRef();

  // On mount, try load previous results
  useState(() => {
    const saved = localStorage.getItem('dpi_results');
    if (saved) {
      try {
        setResults(JSON.parse(saved));
        setDone(true);
      } catch (e) {}
    }
  });

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  };

  const runAnalysis = async () => {
    if (!file) return;
    setRunning(true);
    setDone(false);
    setResults(null);
    setStage(0);

    const formData = new FormData();
    formData.append('pcap', file);
    formData.append('blockedApps', JSON.stringify(blockedApps));
    formData.append('blockedIPs', JSON.stringify(blockedIPs));
    formData.append('blockedDomains', JSON.stringify(blockedDomains));

    try {
      // Simulate stages for UI
      const stageInterval = setInterval(() => {
        setStage(s => Math.min(s + 1, STAGES.length - 2));
      }, 800);

      const res = await fetch('http://localhost:3001/api/analyze', {
        method: 'POST',
        body: formData,
      });

      clearInterval(stageInterval);

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'API Error');
      }

      const data = await res.json();
      setStage(STAGES.length - 1);
      setTimeout(() => {
        setResults(data);
        localStorage.setItem('dpi_results', JSON.stringify(data));
        setRunning(false);
        setDone(true);
        setStage(-1);
      }, 500);

    } catch (error) {
      alert('Analysis failed: ' + error.message);
      setRunning(false);
      setStage(-1);
    }
  };

  const downloadPDF = async () => {
    if (!results) return;
    setDownloadingPdf(true);
    try {
      const res = await fetch('http://localhost:3001/api/report/pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(results),
      });
      if (!res.ok) throw new Error('Failed to generate PDF');
      
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DPI_Engine_Report_${new Date().getTime()}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err) {
      alert(err.message);
    } finally {
      setDownloadingPdf(false);
    }
  }

  const progress = running && stage >= 0 ? ((stage + 1) / STAGES.length) * 100 : done ? 100 : 0;

  const toggleApp = (app) => {
    setBlockedApps(prev =>
      prev.includes(app) ? prev.filter(a => a !== app) : [...prev, app]
    );
  };

  const addIP = () => {
    const v = ipInput.trim();
    if (v && !blockedIPs.includes(v)) setBlockedIPs(p => [...p, v]);
    setIpInput('');
  };
  const addDomain = () => {
    const v = domInput.trim();
    if (v && !blockedDomains.includes(v)) setBlockedDomains(p => [...p, v]);
    setDomInput('');
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">PCAP Analyzer</h1>
            <p className="page-subtitle">Upload a capture file, configure rules, and run deep packet inspection</p>
          </div>
        </div>
      </div>

      {/* Upload zone */}
      <div
        className={`upload-zone mb-6${dragOver ? ' drag-over' : ''}${file ? ' has-file' : ''}`}
        onClick={() => !file && fileInputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng"
          style={{ display: 'none' }}
          onChange={e => e.target.files[0] && setFile(e.target.files[0])}
        />
        {file ? (
          <>
            <span className="upload-icon">✅</span>
            <div className="upload-title" style={{ color: 'var(--accent-green)' }}>{file.name}</div>
            <div className="upload-sub">{(file.size / 1024).toFixed(1)} KB · Ready to analyze</div>
            <button
              className="btn btn-ghost btn-sm mt-4"
              onClick={e => { e.stopPropagation(); setFile(null); setDone(false); }}
            >
              <X size={14} /> Remove
            </button>
          </>
        ) : (
          <>
            <span className="upload-icon">📡</span>
            <div className="upload-title">Drop your PCAP file here</div>
            <div className="upload-sub">or click to browse · .pcap / .pcapng supported</div>
          </>
        )}
      </div>

      {/* Rules toggle */}
      <div className="card mb-6">
        <button
          className="flex items-center justify-between w-full"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-primary)' }}
          onClick={() => setShowRules(r => !r)}
        >
          <span className="section-title" style={{ marginBottom: 0 }}>
            <Shield size={16} color="var(--accent-cyan)" /> Blocking Rules (Pre-analysis)
          </span>
          {showRules ? <ChevronUp size={16} color="var(--text-muted)" /> : <ChevronDown size={16} color="var(--text-muted)" />}
        </button>

        {showRules && (
          <div className="mt-4">
            {/* Block Apps */}
            <div className="mb-4">
              <div className="text-sm font-semibold mb-2" style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Wifi size={14} /> Block Applications
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {allApps.map(app => (
                  <button
                    key={app}
                    className={`badge ${blockedApps.includes(app) ? 'badge-red' : 'badge-muted'}`}
                    style={{ cursor: 'pointer', border: 'none', padding: '5px 12px', fontSize: 12 }}
                    onClick={() => toggleApp(app)}
                  >
                    {blockedApps.includes(app) && '🚫 '}{app}
                  </button>
                ))}
              </div>
            </div>

            {/* Block IPs */}
            <div className="mb-4">
              <div className="text-sm font-semibold mb-2" style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Globe size={14} /> Block IPs
              </div>
              <div className="flex gap-2 mb-2">
                <input
                  className="input"
                  placeholder="e.g. 192.168.1.50"
                  value={ipInput}
                  onChange={e => setIpInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addIP()}
                />
                <button className="btn btn-secondary btn-sm" onClick={addIP}>Add</button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {blockedIPs.map(ip => (
                  <span key={ip} className="badge badge-red">
                    {ip}
                    <button
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: '0 0 0 4px' }}
                      onClick={() => setBlockedIPs(p => p.filter(x => x !== ip))}
                    >×</button>
                  </span>
                ))}
              </div>
            </div>

            {/* Block Domains */}
            <div>
              <div className="text-sm font-semibold mb-2" style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Globe size={14} /> Block Domains (substring match)
              </div>
              <div className="flex gap-2 mb-2">
                <input
                  className="input"
                  placeholder="e.g. youtube.com"
                  value={domInput}
                  onChange={e => setDomInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addDomain()}
                />
                <button className="btn btn-secondary btn-sm" onClick={addDomain}>Add</button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {blockedDomains.map(d => (
                  <span key={d} className="badge badge-orange">
                    {d}
                    <button
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: '0 0 0 4px' }}
                      onClick={() => setBlockedDomains(p => p.filter(x => x !== d))}
                    >×</button>
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Run button */}
      <div className="flex items-center gap-4 mb-6">
        <button
          className="btn btn-primary btn-lg"
          disabled={!file || running}
          onClick={runAnalysis}
          style={{ opacity: (!file || running) ? 0.6 : 1 }}
        >
          {running ? <><span className="spinner" style={{ borderTopColor: '#000' }} /> Processing...</> : <><Zap size={18} /> Run Analysis</>}
        </button>
        {done && <span className="badge badge-green" style={{ fontSize: 13, padding: '6px 14px' }}><CheckCircle size={14} /> Analysis Complete</span>}
      </div>

      {/* Progress */}
      {(running || done) && (
        <div className="card mb-6">
          <div className="flex justify-between mb-2" style={{ fontSize: 13 }}>
            <span className="text-secondary">
              {running ? STAGES[stage]?.label : 'Complete'}
            </span>
            <span className="text-cyan font-semibold">{progress.toFixed(0)}%</span>
          </div>
          <div className="progress-bar-wrap mb-4">
            <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
          </div>
          {running && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {STAGES.map((s, i) => (
                <div key={s.id} className="flex items-center gap-2" style={{ fontSize: 12 }}>
                  {i < stage ? (
                    <CheckCircle size={14} color="var(--accent-green)" />
                  ) : i === stage ? (
                    <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
                  ) : (
                    <span style={{ width: 14, height: 14, borderRadius: '50%', border: '1px solid var(--bg-600)', display: 'inline-block' }} />
                  )}
                  <span style={{ color: i <= stage ? 'var(--text-primary)' : 'var(--text-muted)' }}>{s.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Results */}
      {done && results && (
        <div className="fade-in">
          <div className="section-title"><FileText size={16} color="var(--accent-cyan)" /> Analysis Report</div>
          <div className="grid-4 mb-6">
            {[
              { label: 'Total Packets', value: results.stats.totalPackets.toLocaleString(), color: 'var(--accent-cyan)' },
              { label: 'Forwarded',     value: results.stats.forwarded.toLocaleString(), color: 'var(--accent-green)' },
              { label: 'Dropped',       value: results.stats.dropped.toLocaleString(), color: 'var(--accent-red)' },
              { label: 'Active Flows',  value: results.stats.activeFlows.toLocaleString(), color: 'var(--accent-purple)' },
            ].map(s => (
              <div key={s.label} className="card" style={{ textAlign: 'center', padding: 20 }}>
                <div className="stat-label mb-1">{s.label}</div>
                <div style={{ fontSize: 32, fontWeight: 700, color: s.color }}>{s.value}</div>
              </div>
            ))}
          </div>

          {/* Detected apps */}
          <div className="card mb-6">
            <div className="section-title"><Wifi size={16} color="var(--accent-purple)" /> Detected Applications</div>
            {results.appBreakdown.length === 0 ? (
               <div className="text-muted p-4">No applications detected.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {results.appBreakdown.map(app => {
                  const pct = ((app.packets / results.stats.totalPackets) * 100).toFixed(1);
                  const isBlocked = blockedApps.includes(app.name);
                  return (
                    <div key={app.name} className="flex items-center gap-3">
                      <span style={{ width: 100, color: app.color, fontWeight: 600, fontSize: 13 }}>{app.name}</span>
                      <div className="progress-bar-wrap" style={{ flex: 1 }}>
                        <div
                          className="progress-bar-fill"
                          style={{ width: `${Math.max(pct, 1)}%`, background: isBlocked ? '#ef4444' : `${app.color}cc`, boxShadow: isBlocked ? '0 0 8px rgba(239,68,68,0.4)' : `0 0 8px ${app.color}55` }}
                        />
                      </div>
                      <span className="text-secondary" style={{ width: 90, textAlign: 'right', fontSize: 12 }}>
                        {app.packets.toLocaleString()} · {pct}%
                      </span>
                      {isBlocked && <span className="badge badge-red" style={{ fontSize: 10 }}>Blocked</span>}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="flex gap-3">
            <button className="btn btn-primary" onClick={downloadPDF} disabled={downloadingPdf}>
              {downloadingPdf ? <span className="spinner" style={{width: 14, height: 14, borderTopColor: '#000'}}/> : '📄 '} Download PDF Report
            </button>
            <button className="btn btn-secondary" onClick={() => {
              const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(results, null, 2));
              const downloadAnchorNode = document.createElement('a');
              downloadAnchorNode.setAttribute("href", dataStr);
              downloadAnchorNode.setAttribute("download", "dpi_report.json");
              document.body.appendChild(downloadAnchorNode);
              downloadAnchorNode.click();
              downloadAnchorNode.remove();
            }}>
              📋 Export raw JSON
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

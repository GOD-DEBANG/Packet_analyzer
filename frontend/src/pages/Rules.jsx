import { useState } from 'react';
import { Shield, Plus, Trash2, Wifi, Globe } from 'lucide-react';
import { allApps, defaultBlockedApps, defaultBlockedIPs, defaultBlockedDomains } from '../data/mockAnalysis';

const APP_ICONS = {
  YouTube: '▶️', Facebook: '📘', Google: '🔍', Netflix: '🎬',
  Instagram: '📷', Twitter: '🐦', TikTok: '🎵', Discord: '💬',
  Zoom: '📹', WhatsApp: '📱', Telegram: '✈️', Spotify: '🎧',
  GitHub: '🐙', Amazon: '📦', Microsoft: '🪟', Cloudflare: '🔶',
};

const APP_COLORS_MAP = {
  YouTube: '#ff0000', Facebook: '#1877f2', Google: '#4285f4', Netflix: '#e50914',
  Instagram: '#e1306c', Twitter: '#1da1f2', TikTok: '#69c9d0', Discord: '#5865f2',
  Zoom: '#2d8cff', WhatsApp: '#25d366', Telegram: '#26a5e4', Spotify: '#1db954',
  GitHub: '#f0f6fc', Amazon: '#ff9900', Microsoft: '#00a4ef', Cloudflare: '#f48120',
};

export default function Rules() {
  const [blockedApps, setBlockedApps] = useState(defaultBlockedApps);
  const [blockedIPs, setBlockedIPs] = useState(defaultBlockedIPs);
  const [blockedDomains, setBlockedDomains] = useState(defaultBlockedDomains);
  const [ipInput, setIpInput] = useState('');
  const [domInput, setDomInput] = useState('');

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
            <h1 className="page-title">Rules Manager</h1>
            <p className="page-subtitle">Configure blocking rules — applied to all future analyses</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="badge badge-cyan">{blockedApps.length} apps</span>
            <span className="badge badge-red">{blockedIPs.length} IPs</span>
            <span className="badge badge-orange">{blockedDomains.length} domains</span>
          </div>
        </div>
      </div>

      {/* App toggles */}
      <div className="card mb-6">
        <div className="section-title"><Wifi size={16} color="var(--accent-cyan)" /> Application Blocking</div>
        <p className="text-secondary text-sm mb-4">
          Toggle applications to block. Blocked apps are identified via SNI extraction from TLS Client Hello packets.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
          {allApps.map(app => {
            const isBlocked = blockedApps.includes(app);
            const color = APP_COLORS_MAP[app] || '#94a3b8';
            return (
              <div
                key={app}
                onClick={() => toggleApp(app)}
                style={{
                  padding: '12px 16px',
                  borderRadius: 'var(--radius-sm)',
                  border: `1px solid ${isBlocked ? 'rgba(239,68,68,0.4)' : 'var(--border-subtle)'}`,
                  background: isBlocked ? 'rgba(239,68,68,0.08)' : 'var(--bg-800)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  transition: 'all 0.2s',
                }}
              >
                <div className="flex items-center gap-2">
                  <span style={{ fontSize: 18 }}>{APP_ICONS[app] || '🌐'}</span>
                  <span style={{ fontWeight: 600, fontSize: 13, color: isBlocked ? 'var(--accent-red)' : color }}>
                    {app}
                  </span>
                </div>
                <label className="toggle" onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={isBlocked} onChange={() => toggleApp(app)} />
                  <span className="toggle-track" />
                </label>
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid-2">
        {/* Blocked IPs */}
        <div className="card">
          <div className="section-title"><Globe size={16} color="var(--accent-red)" /> Blocked Source IPs</div>
          <p className="text-secondary text-sm mb-4">
            All traffic originating from these IPs will be dropped regardless of application.
          </p>
          <div className="flex gap-2 mb-4">
            <input
              className="input"
              placeholder="192.168.1.50"
              value={ipInput}
              onChange={e => setIpInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addIP()}
            />
            <button className="btn btn-primary btn-sm" onClick={addIP}>
              <Plus size={14} />
            </button>
          </div>

          {blockedIPs.length === 0 ? (
            <div className="empty-state" style={{ padding: '24px 0' }}>
              <div className="empty-state-icon" style={{ fontSize: 28 }}>🛈</div>
              <div className="empty-state-text" style={{ fontSize: 13 }}>No IPs blocked</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {blockedIPs.map(ip => (
                <div
                  key={ip}
                  className="flex items-center justify-between"
                  style={{
                    padding: '10px 14px',
                    background: 'var(--accent-red-dim)',
                    border: '1px solid rgba(239,68,68,0.25)',
                    borderRadius: 'var(--radius-sm)',
                  }}
                >
                  <span className="mono text-red">{ip}</span>
                  <button
                    className="btn btn-danger btn-sm"
                    style={{ padding: '4px 8px' }}
                    onClick={() => setBlockedIPs(p => p.filter(x => x !== ip))}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Blocked Domains */}
        <div className="card">
          <div className="section-title"><Globe size={16} color="var(--accent-orange)" /> Blocked Domains</div>
          <p className="text-secondary text-sm mb-4">
            Substring match against SNI field. E.g., <span className="mono text-cyan">youtube.com</span> will block all subdomains.
          </p>
          <div className="flex gap-2 mb-4">
            <input
              className="input"
              placeholder="youtube.com"
              value={domInput}
              onChange={e => setDomInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addDomain()}
            />
            <button className="btn btn-primary btn-sm" onClick={addDomain}>
              <Plus size={14} />
            </button>
          </div>

          {blockedDomains.length === 0 ? (
            <div className="empty-state" style={{ padding: '24px 0' }}>
              <div className="empty-state-icon" style={{ fontSize: 28 }}>🛈</div>
              <div className="empty-state-text" style={{ fontSize: 13 }}>No domains blocked</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {blockedDomains.map(d => (
                <div
                  key={d}
                  className="flex items-center justify-between"
                  style={{
                    padding: '10px 14px',
                    background: 'rgba(249,115,22,0.08)',
                    border: '1px solid rgba(249,115,22,0.25)',
                    borderRadius: 'var(--radius-sm)',
                  }}
                >
                  <span className="mono" style={{ color: 'var(--accent-orange)' }}>{d}</span>
                  <button
                    className="btn btn-danger btn-sm"
                    style={{ padding: '4px 8px' }}
                    onClick={() => setBlockedDomains(p => p.filter(x => x !== d))}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Active summary */}
      <div className="card mt-6" style={{ background: 'var(--bg-800)', borderColor: 'var(--border-glow)' }}>
        <div className="section-title"><Shield size={16} color="var(--accent-cyan)" /> Active Policy Summary</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          <div>
            <div className="stat-label mb-2">Blocked Applications ({blockedApps.length})</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {blockedApps.map(a => <span key={a} className="badge badge-red">{a}</span>)}
              {blockedApps.length === 0 && <span className="text-muted text-sm">None</span>}
            </div>
          </div>
          <div>
            <div className="stat-label mb-2">Blocked IPs ({blockedIPs.length})</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {blockedIPs.map(ip => <span key={ip} className="badge badge-red mono">{ip}</span>)}
              {blockedIPs.length === 0 && <span className="text-muted text-sm">None</span>}
            </div>
          </div>
          <div>
            <div className="stat-label mb-2">Blocked Domains ({blockedDomains.length})</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {blockedDomains.map(d => <span key={d} className="badge badge-orange mono">{d}</span>)}
              {blockedDomains.length === 0 && <span className="text-muted text-sm">None</span>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

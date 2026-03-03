import { Activity, ArrowDownRight, ArrowUpRight, Cpu, GitBranch, Layers, Zap } from 'lucide-react';
import { mockStats, mockAppBreakdown, mockFlows, formatBytes, APP_COLORS } from '../data/mockAnalysis';
import { Link } from 'react-router-dom';

function AnimatedNumber({ value }) {
  return <span>{value.toLocaleString()}</span>;
}

export default function Dashboard() {
  const blockedFlows = mockFlows.filter(f => f.blocked).length;

  return (
    <div className="fade-in">
      {/* Hero */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Cpu size={28} color="var(--accent-cyan)" style={{ filter: 'drop-shadow(0 0 8px var(--accent-cyan))' }} />
          <h1 className="page-title" style={{ fontSize: 30 }}>
            <span className="gradient-text">DPI Engine</span> Dashboard
          </h1>
        </div>
        <p className="page-subtitle">
          Real-time deep packet inspection · Multi-threaded · SNI-aware · Application-layer filtering
        </p>
        <div className="flex gap-2 mt-4">
          <Link to="/analyzer" className="btn btn-primary">
            <Zap size={16} /> Run Analysis
          </Link>
          <Link to="/rules" className="btn btn-secondary">
            <Layers size={16} /> Manage Rules
          </Link>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid-4 mb-8">
        <div className="stat-card" style={{ animationDelay: '0ms' }}>
          <div className="stat-icon stat-icon-cyan"><Activity size={22} /></div>
          <div className="stat-info">
            <div className="stat-label">Total Packets</div>
            <div className="stat-value"><AnimatedNumber value={mockStats.totalPackets} /></div>
            <div className="stat-sub">{formatBytes(mockStats.totalBytes)} processed</div>
          </div>
        </div>
        <div className="stat-card" style={{ animationDelay: '80ms' }}>
          <div className="stat-icon stat-icon-green"><ArrowUpRight size={22} /></div>
          <div className="stat-info">
            <div className="stat-label">Forwarded</div>
            <div className="stat-value" style={{ color: 'var(--accent-green)' }}>
              <AnimatedNumber value={mockStats.forwarded} />
            </div>
            <div className="stat-sub">{((mockStats.forwarded / mockStats.totalPackets) * 100).toFixed(1)}% pass rate</div>
          </div>
        </div>
        <div className="stat-card" style={{ animationDelay: '160ms' }}>
          <div className="stat-icon stat-icon-red"><ArrowDownRight size={22} /></div>
          <div className="stat-info">
            <div className="stat-label">Dropped</div>
            <div className="stat-value" style={{ color: 'var(--accent-red)' }}>
              <AnimatedNumber value={mockStats.dropped} />
            </div>
            <div className="stat-sub">{((mockStats.dropped / mockStats.totalPackets) * 100).toFixed(1)}% blocked</div>
          </div>
        </div>
        <div className="stat-card" style={{ animationDelay: '240ms' }}>
          <div className="stat-icon stat-icon-purple"><GitBranch size={22} /></div>
          <div className="stat-info">
            <div className="stat-label">Active Flows</div>
            <div className="stat-value"><AnimatedNumber value={mockStats.activeFlows} /></div>
            <div className="stat-sub">{blockedFlows} flows blocked</div>
          </div>
        </div>
      </div>

      {/* App breakdown + recent flows */}
      <div className="grid-2 mb-8">
        {/* App Breakdown */}
        <div className="card card-cyan">
          <div className="section-title"><Layers size={16} color="var(--accent-cyan)" /> Application Breakdown</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {mockAppBreakdown.slice(0, 8).map(app => {
              const pct = ((app.packets / mockStats.totalPackets) * 100).toFixed(1);
              return (
                <div key={app.name}>
                  <div className="flex justify-between mb-1" style={{ fontSize: 13 }}>
                    <span style={{ color: app.color, fontWeight: 600 }}>{app.name}</span>
                    <span className="text-secondary">{app.packets.toLocaleString()} pkts · {pct}%</span>
                  </div>
                  <div className="progress-bar-wrap">
                    <div
                      className="progress-bar-fill"
                      style={{
                        width: `${pct}%`,
                        background: `linear-gradient(90deg, ${app.color}cc, ${app.color})`,
                        boxShadow: `0 0 8px ${app.color}55`,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Detections */}
        <div className="card">
          <div className="section-title"><Activity size={16} color="var(--accent-purple)" /> Recent Detections</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {mockFlows.slice(0, 9).map(flow => (
              <div
                key={flow.id}
                className="flex items-center justify-between"
                style={{
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-sm)',
                  background: flow.blocked ? 'var(--accent-red-dim)' : 'var(--bg-800)',
                  border: `1px solid ${flow.blocked ? 'rgba(239,68,68,0.2)' : 'var(--border-subtle)'}`,
                }}
              >
                <div>
                  <span
                    className={`app-${flow.app.toLowerCase()}`}
                    style={{ fontWeight: 600, fontSize: 13 }}
                  >
                    {flow.app}
                  </span>
                  {flow.sni && (
                    <span className="text-muted font-mono" style={{ fontSize: 11, marginLeft: 8 }}>
                      {flow.sni}
                    </span>
                  )}
                </div>
                <span className={`badge ${flow.blocked ? 'badge-red' : 'badge-green'}`}>
                  {flow.blocked ? 'Blocked' : 'Fwd'}
                </span>
              </div>
            ))}
          </div>

          <Link to="/flows" className="btn btn-ghost btn-sm w-full mt-4" style={{ justifyContent: 'center' }}>
            View all {mockFlows.length} flows →
          </Link>
        </div>
      </div>

      {/* Engine info bar */}
      <div className="card" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 0 }}>
        {[
          { label: 'Processing Speed', value: `${mockStats.processingTimeMs}ms`, sub: 'last analysis' },
          { label: 'TCP Packets',  value: mockStats.tcpPackets.toLocaleString(), sub: 'transport layer' },
          { label: 'UDP Packets',  value: mockStats.udpPackets.toLocaleString(), sub: 'transport layer' },
          { label: 'Architecture', value: 'Multi-thread', sub: '2 LBs · 4 FPs' },
        ].map((item, i) => (
          <div
            key={i}
            style={{
              padding: '16px 20px',
              borderRight: i < 3 ? '1px solid var(--border-subtle)' : 'none',
            }}
          >
            <div className="stat-label mb-1">{item.label}</div>
            <div className="font-bold text-cyan" style={{ fontSize: 20 }}>{item.value}</div>
            <div className="text-muted text-xs">{item.sub}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

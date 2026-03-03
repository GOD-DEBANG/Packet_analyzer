import React, { useState, useEffect } from 'react';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend,
  AreaChart, Area,
} from 'recharts';
import { BarChart3, Layers, Clock, Activity } from 'lucide-react';
import { formatBytes } from '../data/mockAnalysis';

const RADIAN = Math.PI / 180;
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }) => {
  if (percent < 0.04) return null;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central"
      style={{ fontSize: 11, fontWeight: 600 }}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

const tooltipStyle = {
  backgroundColor: 'var(--bg-800)',
  border: '1px solid var(--border-subtle)',
  borderRadius: 8,
  color: 'var(--text-primary)',
  fontSize: 13,
};

export default function Traffic() {
  const [results, setResults] = useState(null);

  useEffect(() => {
    const saved = localStorage.getItem('dpi_results');
    if (saved) {
      try { setResults(JSON.parse(saved)); } catch(e){}
    }
  }, []);

  if (!results) {
    return (
      <div className="fade-in" style={{display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh'}}>
        <Activity size={48} color="var(--text-muted)" style={{marginBottom: 16}} />
        <h2 style={{color: 'var(--text-primary)'}}>No Traffic Data Available</h2>
        <p style={{color: 'var(--text-secondary)'}}>Go to the Analyzer page and process a PCAP file first.</p>
      </div>
    );
  }

  const { stats, appBreakdown, protocolBreakdown, timelineData } = results;
  const barData = appBreakdown.slice(0, 10);

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1 className="page-title">Traffic Analysis</h1>
        <p className="page-subtitle">Application breakdown, protocol distribution, and packet timeline</p>
      </div>

      {/* Summary row */}
      <div className="grid-3 mb-8">
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="stat-label mb-1">Total Packets</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--accent-cyan)' }}>{stats.totalPackets.toLocaleString()}</div>
          <div className="text-muted text-sm">{formatBytes(stats.totalBytes)}</div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="stat-label mb-1">Unique Apps Detected</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--accent-purple)' }}>{appBreakdown.length}</div>
          <div className="text-muted text-sm">across all flows</div>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="stat-label mb-1">Drop Rate</div>
          <div style={{ fontSize: 32, fontWeight: 700, color: 'var(--accent-red)' }}>
            {((stats.dropped / stats.totalPackets) * 100 || 0).toFixed(1)}%
          </div>
          <div className="text-muted text-sm">{stats.dropped.toLocaleString()} packets blocked</div>
        </div>
      </div>

      {/* Pie + Bar */}
      <div className="grid-2 mb-8">
        {/* Doughnut — Protocol */}
        <div className="card card-purple">
          <div className="section-title"><Layers size={16} color="var(--accent-purple)" /> Protocol Distribution</div>
          <div className="chart-wrap" style={{ height: 280 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolBreakdown}
                  cx="50%" cy="50%"
                  innerRadius={70} outerRadius={110}
                  paddingAngle={3}
                  dataKey="value"
                  labelLine={false}
                  label={renderCustomLabel}
                >
                  {protocolBreakdown.map((entry, i) => (
                    <Cell
                      key={entry.name}
                      fill={['#00f5ff', '#a855f7', '#f97316'][i]}
                      stroke="none"
                    />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} formatter={(v) => [v.toLocaleString(), 'Packets']} />
                <Legend
                  formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Doughnut — App share */}
        <div className="card card-cyan">
          <div className="section-title"><BarChart3 size={16} color="var(--accent-cyan)" /> Top App Distribution</div>
          <div className="chart-wrap" style={{ height: 280 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={appBreakdown.slice(0, 8)}
                  cx="50%" cy="50%"
                  outerRadius={110}
                  paddingAngle={2}
                  dataKey="packets"
                  nameKey="name"
                  labelLine={false}
                  label={renderCustomLabel}
                >
                  {appBreakdown.slice(0, 8).map((entry) => (
                    <Cell key={entry.name} fill={entry.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} formatter={(v) => [v.toLocaleString(), 'Packets']} />
                <Legend
                  formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bar chart — top apps */}
      <div className="card mb-8">
        <div className="section-title"><BarChart3 size={16} color="var(--accent-cyan)" /> Packets per Application</div>
        <div className="chart-wrap" style={{ height: 280 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
              <Bar dataKey="packets" radius={[4, 4, 0, 0]}>
                {barData.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Timeline Area chart */}
      <div className="card">
        <div className="section-title"><Clock size={16} color="var(--accent-purple)" /> Packet Timeline</div>
        <div className="chart-wrap" style={{ height: 240 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timelineData} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="gradPackets" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#00f5ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#00f5ff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradDropped" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{value}</span>} />
              <Area type="monotone" dataKey="packets" stroke="#00f5ff" strokeWidth={2} fill="url(#gradPackets)" name="Forwarded" dot={false} />
              <Area type="monotone" dataKey="dropped" stroke="#ef4444" strokeWidth={2} fill="url(#gradDropped)" name="Dropped" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

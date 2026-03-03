import { useState, useEffect, useMemo } from 'react';
import { Network, Search, ChevronDown, ChevronUp, ArrowUpDown, Activity } from 'lucide-react';
import { formatBytes, getAppClass } from '../data/mockAnalysis';

const COLUMNS = [
  { key: 'srcIp',    label: 'Source IP',   sortable: true },
  { key: 'dstIp',    label: 'Dest IP',     sortable: true },
  { key: 'app',      label: 'Application', sortable: true },
  { key: 'sni',      label: 'SNI / Host',  sortable: false },
  { key: 'protocol', label: 'Proto',       sortable: true },
  { key: 'packets',  label: 'Packets',     sortable: true },
  { key: 'bytes',    label: 'Bytes',       sortable: true },
  { key: 'blocked',  label: 'Status',      sortable: true },
];

export default function Flows() {
  const [results, setResults] = useState(null);
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState('packets');
  const [sortDir, setSortDir] = useState('desc');
  const [expanded, setExpanded] = useState(null);
  const [filter, setFilter] = useState('all'); // all | blocked | forwarded

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
        <h2 style={{color: 'var(--text-primary)'}}>No Flow Data Available</h2>
        <p style={{color: 'var(--text-secondary)'}}>Go to the Analyzer page and process a PCAP file first.</p>
      </div>
    );
  }

  const baseFlows = results.flows || [];

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  const flows = useMemo(() => {
    let list = [...baseFlows];

    // Filter
    if (filter === 'blocked') list = list.filter(f => f.blocked);
    if (filter === 'forwarded') list = list.filter(f => !f.blocked);

    // Search
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(f =>
        f.srcIp.includes(q) ||
        f.dstIp.includes(q) ||
        f.app.toLowerCase().includes(q) ||
        f.sni.toLowerCase().includes(q) ||
        f.protocol.toLowerCase().includes(q)
      );
    }

    // Sort
    list.sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (typeof av === 'boolean') return sortDir === 'asc' ? (av ? 1 : -1) : (av ? -1 : 1);
      if (typeof av === 'number') return sortDir === 'asc' ? av - bv : bv - av;
      return sortDir === 'asc'
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });

    return list;
  }, [search, sortKey, sortDir, filter, baseFlows]);

  const blocked = baseFlows.filter(f => f.blocked).length;
  const forwarded = baseFlows.length - blocked;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-row">
          <div>
            <h1 className="page-title">Flow Inspector</h1>
            <p className="page-subtitle">All detected connections with classification and SNI details</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="badge badge-green">{forwarded} Forwarded</span>
            <span className="badge badge-red">{blocked} Blocked</span>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-3 mb-4">
        <div style={{ position: 'relative', flex: 1, maxWidth: 380 }}>
          <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            className="input"
            placeholder="Search IP, app, SNI, protocol..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ paddingLeft: 36 }}
          />
        </div>
        <div className="flex gap-1">
          {[
            { id: 'all',       label: 'All',       count: baseFlows.length },
            { id: 'forwarded', label: 'Forwarded',  count: forwarded },
            { id: 'blocked',   label: 'Blocked',    count: blocked },
          ].map(f => (
            <button
              key={f.id}
              className={`btn btn-sm ${filter === f.id ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setFilter(f.id)}
            >
              {f.label} ({f.count})
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 30 }} />
              {COLUMNS.map(col => (
                <th
                  key={col.key}
                  onClick={() => col.sortable && toggleSort(col.key)}
                  style={{ cursor: col.sortable ? 'pointer' : 'default' }}
                >
                  <span className="flex items-center gap-1">
                    {col.label}
                    {col.sortable && (
                      <ArrowUpDown
                        size={11}
                        color={sortKey === col.key ? 'var(--accent-cyan)' : 'var(--text-muted)'}
                      />
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {flows.length === 0 ? (
              <tr>
                <td colSpan={COLUMNS.length + 1} style={{ textAlign: 'center', padding: 48 }}>
                  <div className="text-muted">No flows match your search</div>
                </td>
              </tr>
            ) : (
              flows.map(flow => (
                <>
                  <tr
                    key={flow.id}
                    className={flow.blocked ? 'blocked-row' : ''}
                    style={{ cursor: 'pointer' }}
                    onClick={() => setExpanded(expanded === flow.id ? null : flow.id)}
                  >
                    <td style={{ color: 'var(--text-muted)', textAlign: 'center' }}>
                      {expanded === flow.id
                        ? <ChevronUp size={14} />
                        : <ChevronDown size={14} />}
                    </td>
                    <td className="mono" style={{ color: 'var(--text-primary)', fontSize: 12 }}>{flow.srcIp}</td>
                    <td className="mono" style={{ fontSize: 12 }}>{flow.dstIp}</td>
                    <td>
                      <span className={getAppClass(flow.app)} style={{ fontWeight: 600, fontSize: 13 }}>
                        {flow.app}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 11, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {flow.sni || <span className="text-muted">—</span>}
                    </td>
                    <td>
                      <span className={`badge ${flow.protocol === 'TCP' ? 'badge-cyan' : 'badge-purple'}`}>
                        {flow.protocol}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-primary)' }}>{flow.packets.toLocaleString()}</td>
                    <td style={{ fontSize: 12 }}>{formatBytes(flow.bytes)}</td>
                    <td>
                      <span className={`badge ${flow.blocked ? 'badge-red' : 'badge-green'}`}>
                        {flow.blocked ? '🚫 Blocked' : '✓ Forwarded'}
                      </span>
                    </td>
                  </tr>
                  {expanded === flow.id && (
                    <tr key={`${flow.id}-detail`}>
                      <td colSpan={COLUMNS.length + 1} style={{ padding: 0 }}>
                        <div className="flow-detail-panel">
                          <div className="detail-field">
                            <span className="detail-label">Source</span>
                            <span className="detail-value">{flow.srcIp}:{flow.srcPort}</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">Destination</span>
                            <span className="detail-value">{flow.dstIp}:{flow.dstPort}</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">Protocol</span>
                            <span className="detail-value">{flow.protocol} ({flow.protocol === 'TCP' ? '6' : '17'})</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">SNI / Host</span>
                            <span className="detail-value">{flow.sni || 'Not detected'}</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">Application</span>
                            <span className={`detail-value ${getAppClass(flow.app)}`}>{flow.app}</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">Flow State</span>
                            <span className="detail-value">{flow.state}</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">Packets</span>
                            <span className="detail-value">{flow.packets.toLocaleString()}</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">Bytes</span>
                            <span className="detail-value">{formatBytes(flow.bytes)}</span>
                          </div>
                          <div className="detail-field">
                            <span className="detail-label">Action</span>
                            <span className="detail-value" style={{ color: flow.blocked ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                              {flow.blocked ? 'DROP' : 'FORWARD'}
                            </span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex justify-between items-center mt-3 text-sm text-muted">
        <span>Showing {flows.length} of {baseFlows.length} flows</span>
        <span>Click a row to expand connection details</span>
      </div>
    </div>
  );
}

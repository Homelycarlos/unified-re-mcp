import React, { useState, useEffect } from 'react';
import { ShieldAlert, Fingerprint, Activity, Terminal, Database, RefreshCw, Server, CheckCircle2, XCircle, Search } from 'lucide-react';
import './index.css';

// Mock data to simulate the NexusRE MCP API response since the dashboard connects externally
const MOCK_SESSIONS = [
  { session_id: 'ida_master', backend: 'ida', url: '127.0.0.1:10101', status: 'ALIVE', is_default: true },
  { session_id: 'x64dbg_live', backend: 'x64dbg', url: '127.0.0.1:10103', status: 'DEAD', is_default: false },
];

const MOCK_SIGS = [
  { name: 'Game Manager', pattern: '48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90', status: 'ALIVE' },
  { name: 'Network Manager', pattern: '48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 84', status: 'ALIVE' },
  { name: 'Profile Manager', pattern: '48 8B 05 ?? ?? ?? ?? 48 8B 80', status: 'ALIVE' },
  { name: 'Actor (Precise)', pattern: '0F 29 69 50 0F 29 41 40 0F 29 61 30', status: 'DEAD' },
  { name: 'Entity List', pattern: '48 8B 15 ?? ?? ?? ?? 48 8D 4C 24 20', status: 'DEAD' },
];

const MOCK_LOGS = [
  { time: '10:42:01', tool: 'scan_aob', success: true, detail: 'Found Game Manager at 0x140B829A0' },
  { time: '10:42:05', tool: 'read_memory', success: true, detail: 'Read 64 bytes from 0x140B829A0' },
  { time: '10:43:12', tool: 'scan_aob', success: false, detail: 'Pattern Actor (Precise) failed.' },
];

function App() {
  const [recovering, setRecovering] = useState(false);
  const [sigs, setSigs] = useState(MOCK_SIGS);
  const [search, setSearch] = useState('');

  const handleRecover = () => {
    setRecovering(true);
    // Simulate MCP recovery delay
    setTimeout(() => {
      setSigs(sigs.map(s => ({ ...s, status: 'ALIVE' })));
      setRecovering(false);
    }, 2500);
  };

  const deadCount = sigs.filter(s => s.status === 'DEAD').length;

  return (
    <div className="app-container">
      <header>
        <h1><ShieldAlert size={36} color="#22d3ee" /> NexusRE OVERSEER</h1>
        <div style={{ display: 'flex', gap: '16px' }}>
          <button className="primary" style={{ background: 'transparent' }}>
             <Server size={18} /> API Docs
          </button>
          <button className={deadCount > 0 ? "danger" : "primary"} onClick={handleRecover} disabled={recovering}>
            <RefreshCw size={18} className={recovering ? "loading" : ""} />
            {recovering ? 'AI Recovering...' : 'Auto-Recover Sigs'}
          </button>
        </div>
      </header>

      <div className="grid-top">
        {/* Connection Status Panel */}
        <div className="panel">
          <h2><Activity size={24} color="#a1a1aa" /> Active Sessions</h2>
          <div style={{ marginTop: '20px' }}>
            {MOCK_SESSIONS.map(s => (
              <div key={s.session_id} className="session-item">
                <div className="session-meta">
                  <div className={`status-dot ${s.status === 'ALIVE' ? 'green' : 'red'}`} />
                  <div>
                    <div className="session-id">{s.session_id} {s.is_default && <span style={{ fontSize: '0.7em', padding: '2px 6px', background: '#27272a', borderRadius: '4px', marginLeft: '8px' }}>DEFAULT</span>}</div>
                    <div className="session-type">{s.backend} via {s.url}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Brain DB / Signature Health Panel */}
        <div className="panel">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2><Fingerprint size={24} color="#a1a1aa" /> Signature Health (r6siege)</h2>
            <div style={{ display: 'flex', alignItems: 'center', background: '#000', padding: '6px 12px', borderRadius: '8px', border: '1px solid #27272a' }}>
              <Search size={16} color="#a1a1aa" style={{ marginRight: '8px' }} />
              <input 
                type="text" 
                placeholder="Search Brain DB..." 
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', color: '#fff', outline: 'none', width: '150px' }} 
              />
            </div>
          </div>
          
          <div className="sig-list" style={{ marginTop: '20px' }}>
            {sigs.filter(s => s.name.toLowerCase().includes(search.toLowerCase())).map((sig, i) => (
              <div key={i} className={`sig-card ${sig.status === 'DEAD' ? 'dead' : ''}`}>
                <div className="sig-name">
                  {sig.name}
                  {sig.status === 'ALIVE' ? <CheckCircle2 size={18} color="#4ade80"/> : <XCircle size={18} color="#f87171"/>}
                </div>
                <div className="sig-pattern">{sig.pattern}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Audit Log / Terminal Panel */}
      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <h2 style={{ padding: '20px 24px 10px' }}><Terminal size={24} color="#a1a1aa" /> MCP Command Audit Log</h2>
        <div className="terminal">
          {MOCK_LOGS.map((log, i) => (
            <div key={i} className="log-line">
              <span className="log-time">[{log.time}]</span>
              <span className="log-tool">{log.tool}()</span>
              <span className={log.success ? "log-success" : "log-fail"}>
                {log.success ? '-> OK' : '-> ERR'}
              </span>
              <span style={{ color: '#d4d4d8', marginLeft: '12px' }}>{log.detail}</span>
            </div>
          ))}
          {recovering && (
            <div className="log-line">
              <span className="log-time">[{new Date().toLocaleTimeString('en-US', { hour12: false })}]</span>
              <span className="log-tool">auto_recover_signatures()</span>
              <span style={{ color: '#fbbf24' }}>-> RUNNING</span>
              <span style={{ color: '#d4d4d8', marginLeft: '12px' }}>AI analyzing xrefs for 'Actor (Precise)'...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;

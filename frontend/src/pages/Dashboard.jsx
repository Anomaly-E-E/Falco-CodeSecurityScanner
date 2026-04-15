import React, { useState, useRef } from 'react';
import useAuth from '../hooks/useAuth';
import api from '../api/client';
import CodeEditor from '../components/CodeEditor';
import ScanResults from '../components/ScanResults';
import ScanHistoryTable from '../components/ScanHistoryTable';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';

const SECTION_LABEL = {
  fontSize: '0.7rem',
  fontFamily: 'var(--font-mono)',
  textTransform: 'uppercase',
  letterSpacing: '0.1em',
  color: 'var(--text-muted)',
  marginBottom: 10,
};

export default function Dashboard() {
  const { user, refreshCredits } = useAuth();
  const [code, setCode] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [historyKey, setHistoryKey] = useState(0);
  const resultsRef = useRef(null);

  const noCredits = (user?.credits ?? 1) <= 0;
  const overLimit = code.length > 400;
  const canScan = code.trim().length > 0 && !overLimit && !noCredits && !scanning;

  async function handleScan() {
    setError('');
    setScanResult(null);
    setScanning(true);

    const { ok, data, error: err } = await api.post('/scans/analyze', { code });
    setScanning(false);

    if (!ok) { setError(err); return; }

    setScanResult(data.scan);
    await refreshCredits();
    setHistoryKey(k => k + 1);

    setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 80);
  }

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '28px 20px 48px' }}>

      <div style={{
        display: 'flex',
        gap: 20,
        marginBottom: 40,
        flexWrap: 'wrap',
      }}>

        <div style={{ flex: '3 1 460px', minWidth: 0 }}>
          <p style={SECTION_LABEL}>scan</p>
          <CodeEditor value={code} onChange={setCode} disabled={scanning} />

          {error && (
            <div className="error-msg" style={{ marginTop: 8 }}>{error}</div>
          )}

          <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={handleScan}
              disabled={!canScan}
              className="btn btn-primary"
              style={{ flex: 1 }}
            >
              {scanning ? <><LoadingSpinner size={13} /> scanning...</> : 'scan code'}
            </button>
            {noCredits && (
              <span style={{ fontSize: '0.75rem', color: 'var(--danger)', flexShrink: 0 }}>
                no credits
              </span>
            )}
          </div>

          <p style={{
            marginTop: 8,
            fontSize: '0.72rem',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
          }}>
            python · javascript · java · c/c++ · max 400 chars
          </p>
        </div>

        <div ref={resultsRef} style={{ flex: '2 1 320px', minWidth: 0 }}>
          <p style={SECTION_LABEL}>results</p>
          {scanResult ? (
            <ScanResults
              vulnerabilities={scanResult.vulnerabilities || []}
              language={scanResult.language}
              scannedAt={scanResult.scannedAt}
            />
          ) : (
            <div style={{
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              background: 'var(--bg-card)',
              height: '100%',
              minHeight: 180,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <EmptyState icon="[/]" message="paste code and scan" />
            </div>
          )}
        </div>
      </div>

      <div>
        <p style={SECTION_LABEL}>history</p>
        <ScanHistoryTable refreshKey={historyKey} />
      </div>
    </div>
  );
}

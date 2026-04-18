import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../api/client';
import ScanResults from '../components/ScanResults';
import LoadingSpinner from '../components/LoadingSpinner';
import { formatDate } from '../utils/formatDate';

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.get(`/scans/${id}`).then(({ ok, data, error: err }) => {
      if (ok) setScan(data);
      else setError(err);
      setLoading(false);
    });
  }, [id]);

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}>
        <LoadingSpinner />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div style={{ maxWidth: 740, margin: '44px auto', padding: '0 24px' }}>
        <div className="error-msg">{error || 'scan not found'}</div>
        <button onClick={() => navigate('/dashboard')} style={{
          marginTop: 12, background: 'none', border: 'none',
          color: 'var(--accent)', cursor: 'pointer', fontSize: '0.85rem', padding: 0,
        }}>
          ← back
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: '32px 24px 56px', animation: 'fadeIn 0.3s ease both' }}>
      <button
        onClick={() => navigate('/dashboard')}
        style={{
          background: 'none', border: 'none',
          color: 'var(--text-muted)', fontSize: '0.82rem',
          fontFamily: 'var(--font-mono)',
          cursor: 'pointer', padding: 0, marginBottom: 24,
          transition: `color var(--duration-fast)`,
        }}
        onMouseEnter={e => e.target.style.color = 'var(--text-primary)'}
        onMouseLeave={e => e.target.style.color = 'var(--text-muted)'}
      >
        ← back
      </button>

      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 18,
        marginBottom: 24,
        flexWrap: 'wrap',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.72rem',
          color: 'var(--accent)',
          border: '1px solid var(--accent)',
          padding: '2px 8px',
          borderRadius: 'var(--radius-sm)',
          opacity: 0.8,
        }}>
          {scan.language}
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem', fontFamily: 'var(--font-mono)' }}>
          {scan.codeLength} chars
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem', fontFamily: 'var(--font-mono)' }}>
          {formatDate(scan.scannedAt)}
        </span>
        <span style={{
          fontSize: '0.78rem',
          color: scan.vulnerabilitiesCount > 0 ? 'var(--danger)' : 'var(--success)',
          fontWeight: 500,
        }}>
          {scan.vulnerabilitiesCount > 0 ? `${scan.vulnerabilitiesCount} issue${scan.vulnerabilitiesCount !== 1 ? 's' : ''}` : 'clean'}
        </span>
      </div>

      <ScanResults
        vulnerabilities={scan.vulnerabilities || []}
        language={scan.language}
        scannedAt={scan.scannedAt}
      />
    </div>
  );
}

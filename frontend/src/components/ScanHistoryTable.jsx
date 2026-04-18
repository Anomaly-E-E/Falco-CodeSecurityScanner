import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import LoadingSpinner from './LoadingSpinner';
import EmptyState from './EmptyState';
import { formatDate } from '../utils/formatDate';

export default function ScanHistoryTable({ refreshKey }) {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const limit = 10;

  const fetchHistory = useCallback(async (p) => {
    setLoading(true);
    setError('');
    const { ok, data } = await api.get(`/scans/history?page=${p}&limit=${limit}`);
    if (ok) {
      setScans(data.scans);
      setTotal(data.totalScans);
    } else {
      setError('failed to load history');
    }
    setLoading(false);
  }, []);

  useEffect(() => { setPage(1); }, [refreshKey]);
  useEffect(() => { fetchHistory(page); }, [page, fetchHistory]);

  const totalPages = Math.ceil(total / limit);

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '36px 0' }}>
        <LoadingSpinner />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ fontSize: '0.82rem', color: 'var(--danger)', padding: '14px 0' }}>
        {error}
      </div>
    );
  }

  if (scans.length === 0) {
    return <EmptyState icon="[--]" message="no scans yet" />;
  }

  return (
    <div>
      <div style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)',
        overflow: 'hidden',
      }}>
        {scans.map((scan, i) => (
          <div
            key={scan.id}
            onClick={() => navigate(`/scans/${scan.id}`)}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '13px 16px',
              borderBottom: i < scans.length - 1 ? '1px solid var(--border-subtle)' : 'none',
              cursor: 'pointer',
              transition: `background var(--duration-fast)`,
              background: 'var(--bg-card)',
              gap: 14,
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-elevated)'}
            onMouseLeave={e => e.currentTarget.style.background = 'var(--bg-card)'}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.7rem',
                color: 'var(--accent)',
                border: '1px solid var(--accent)',
                padding: '2px 7px',
                borderRadius: 'var(--radius-sm)',
                opacity: 0.7,
                flexShrink: 0,
              }}>
                {scan.language}
              </span>
              <span style={{
                color: 'var(--text-muted)',
                fontSize: '0.78rem',
                fontFamily: 'var(--font-mono)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}>
                {formatDate(scan.scannedAt)}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
              <span style={{
                fontSize: '0.78rem',
                fontWeight: 500,
                color: scan.vulnerabilitiesCount > 0 ? 'var(--danger)' : 'var(--success)',
              }}>
                {scan.vulnerabilitiesCount > 0 ? `${scan.vulnerabilitiesCount} found` : 'clean'}
              </span>
              <span style={{ fontSize: '0.78rem', color: 'var(--accent)' }}>→</span>
            </div>
          </div>
        ))}
      </div>

      {totalPages > 1 && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginTop: 14,
          padding: '0 4px',
        }}>
          <button
            onClick={() => setPage(p => p - 1)}
            disabled={page === 1}
            style={{
              background: 'none',
              border: 'none',
              color: page === 1 ? 'var(--border-light)' : 'var(--text-secondary)',
              fontSize: '0.82rem',
              fontFamily: 'var(--font-mono)',
              cursor: page === 1 ? 'default' : 'pointer',
              padding: 0,
            }}
          >
            ← prev
          </button>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
            {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={page >= totalPages}
            style={{
              background: 'none',
              border: 'none',
              color: page >= totalPages ? 'var(--border-light)' : 'var(--text-secondary)',
              fontSize: '0.82rem',
              fontFamily: 'var(--font-mono)',
              cursor: page >= totalPages ? 'default' : 'pointer',
              padding: 0,
            }}
          >
            next →
          </button>
        </div>
      )}
    </div>
  );
}

import React, { useState, useMemo } from 'react';
import VulnerabilityCard from './VulnerabilityCard';
import EmptyState from './EmptyState';

const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };

const DOT_COLORS = {
  HIGH:   'var(--severity-high)',
  MEDIUM: 'var(--severity-med)',
  LOW:    'var(--severity-low)',
};

function Dot({ color }) {
  return (
    <span style={{
      display: 'inline-block',
      width: 7,
      height: 7,
      borderRadius: '50%',
      background: color,
      flexShrink: 0,
    }} />
  );
}

export default function ScanResults({ vulnerabilities, language }) {
  const [sortBy, setSortBy] = useState('severity');

  const counts = useMemo(() =>
    vulnerabilities.reduce((acc, v) => {
      acc[v.severity] = (acc[v.severity] || 0) + 1;
      return acc;
    }, {}),
  [vulnerabilities]);

  const total = vulnerabilities.length;

  const sorted = useMemo(() => {
    const copy = [...vulnerabilities];
    if (sortBy === 'severity') {
      copy.sort((a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3));
    } else {
      copy.sort((a, b) => (a.line ?? 9999) - (b.line ?? 9999));
    }
    return copy;
  }, [vulnerabilities, sortBy]);

  return (
    <div>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 10,
        marginBottom: 14,
        padding: '10px 12px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {language && (
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.72rem',
              color: 'var(--accent)',
              border: '1px solid var(--accent)',
              padding: '1px 7px',
              borderRadius: 3,
              opacity: 0.8,
            }}>
              {language}
            </span>
          )}
          <span style={{
            fontSize: '0.82rem',
            color: total > 0 ? 'var(--danger)' : 'var(--success)',
            fontWeight: 500,
          }}>
            {total === 0 ? 'clean' : `${total} issue${total !== 1 ? 's' : ''}`}
          </span>
          {total > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {['HIGH', 'MEDIUM', 'LOW'].map(sev => counts[sev] ? (
                <span key={sev} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: DOT_COLORS[sev] }}>
                  <Dot color={DOT_COLORS[sev]} />{counts[sev]}
                </span>
              ) : null)}
            </div>
          )}
        </div>

        {total > 1 && (
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            {['severity', 'line'].map(s => (
              <button
                key={s}
                onClick={() => setSortBy(s)}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '0.72rem',
                  color: sortBy === s ? 'var(--accent)' : 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '0 0 1px',
                  borderBottom: sortBy === s ? '1px solid var(--accent)' : '1px solid transparent',
                  transition: 'color 0.1s',
                }}
              >
                {s}
              </button>
            ))}
          </div>
        )}
      </div>

      {total === 0 ? (
        <EmptyState icon="[✓]" message="no issues found" />
      ) : (
        sorted.map((v, i) => (
          <VulnerabilityCard
            key={`${v.type}-${v.line ?? i}`}
            vuln={v}
            style={{ animationDelay: `${i * 0.04}s` }}
          />
        ))
      )}
    </div>
  );
}

import React from 'react';

const cfg = {
  HIGH:   { color: '#E07070', bg: 'rgba(224, 112, 112, 0.12)', border: 'rgba(224, 112, 112, 0.2)' },
  MEDIUM: { color: '#D4A24C', bg: 'rgba(212, 162, 76, 0.12)',  border: 'rgba(212, 162, 76, 0.2)' },
  LOW:    { color: '#6BBF7A', bg: 'rgba(107, 191, 122, 0.12)', border: 'rgba(107, 191, 122, 0.2)' },
};

export default function SeverityBadge({ severity }) {
  const s = cfg[severity] || cfg.LOW;
  return (
    <span style={{
      display: 'inline-block',
      background: s.bg,
      color: s.color,
      border: `1px solid ${s.border}`,
      fontFamily: 'var(--font-mono)',
      fontSize: '0.68rem',
      fontWeight: 500,
      letterSpacing: '0.08em',
      padding: '3px 8px',
      borderRadius: 'var(--radius-sm)',
      textTransform: 'uppercase',
      flexShrink: 0,
    }}>
      {severity}
    </span>
  );
}

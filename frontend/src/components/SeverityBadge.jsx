import React from 'react';

const cfg = {
  HIGH:   { color: '#EF4444', bg: 'rgba(239,68,68,0.1)' },
  MEDIUM: { color: '#F97316', bg: 'rgba(249,115,22,0.1)' },
  LOW:    { color: '#22C55E', bg: 'rgba(34,197,94,0.1)' },
};

export default function SeverityBadge({ severity }) {
  const s = cfg[severity] || cfg.LOW;
  return (
    <span style={{
      display: 'inline-block',
      background: s.bg,
      color: s.color,
      fontFamily: 'var(--font-mono)',
      fontSize: '0.68rem',
      fontWeight: 500,
      letterSpacing: '0.07em',
      padding: '2px 7px',
      borderRadius: 3,
      textTransform: 'uppercase',
      flexShrink: 0,
    }}>
      {severity}
    </span>
  );
}

import React from 'react';

export default function CreditsBadge({ credits }) {
  let color = 'var(--accent)';
  let borderColor = 'var(--accent)';
  let background = 'transparent';

  if (credits !== null && credits <= 0) {
    color = 'var(--danger)';
    borderColor = 'var(--danger)';
    background = 'var(--danger-dim)';
  } else if (credits !== null && credits <= 2) {
    color = 'var(--warning)';
    borderColor = 'var(--warning)';
    background = 'var(--warning-dim)';
  }

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      border: `1px solid ${borderColor}`,
      borderRadius: 'var(--radius-full)',
      padding: '4px 12px',
      fontSize: '0.72rem',
      fontFamily: 'var(--font-mono)',
      color,
      background,
      letterSpacing: '0.04em',
    }}>
      {credits ?? '-'} cr
    </span>
  );
}

import React from 'react';

export default function CreditsBadge({ credits }) {
  let color = 'var(--accent)';
  let borderColor = 'var(--accent)';

  if (credits !== null && credits <= 0) {
    color = 'var(--danger)';
    borderColor = 'var(--danger)';
  } else if (credits !== null && credits <= 2) {
    color = 'var(--warning)';
    borderColor = 'var(--warning)';
  }

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      border: `1px solid ${borderColor}`,
      borderRadius: 20,
      padding: '3px 10px',
      fontSize: '0.75rem',
      fontFamily: 'var(--font-mono)',
      color,
      letterSpacing: '0.03em',
    }}>
      {credits ?? '—'} cr
    </span>
  );
}

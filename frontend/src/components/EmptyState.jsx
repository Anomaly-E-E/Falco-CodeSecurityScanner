import React from 'react';

export default function EmptyState({ icon, message, cta }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '48px 24px',
      gap: 12,
    }}>
      {icon && (
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '1.1rem',
          color: 'var(--text-muted)',
          letterSpacing: '0.06em',
          userSelect: 'none',
          opacity: 0.6,
        }}>
          {icon}
        </span>
      )}
      <p style={{
        color: 'var(--text-muted)',
        fontSize: '0.85rem',
        textAlign: 'center',
        maxWidth: 260,
        lineHeight: 1.6,
        fontFamily: 'var(--font-serif)',
      }}>
        {message}
      </p>
      {cta && (
        <button
          onClick={cta.onClick}
          style={{
            marginTop: 6,
            background: 'none',
            border: 'none',
            color: 'var(--accent)',
            fontSize: '0.85rem',
            cursor: 'pointer',
            padding: 0,
            textDecoration: 'underline',
            textUnderlineOffset: '3px',
          }}
        >
          {cta.label}
        </button>
      )}
    </div>
  );
}

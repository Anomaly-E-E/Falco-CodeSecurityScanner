import React from 'react';

export default function EmptyState({ icon, message, cta }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '40px 20px',
      gap: 10,
    }}>
      {icon && (
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '1rem',
          color: 'var(--border-light)',
          letterSpacing: '0.05em',
          userSelect: 'none',
        }}>
          {icon}
        </span>
      )}
      <p style={{
        color: 'var(--text-muted)',
        fontSize: '0.82rem',
        textAlign: 'center',
        maxWidth: 240,
        lineHeight: 1.5,
      }}>
        {message}
      </p>
      {cta && (
        <button
          onClick={cta.onClick}
          style={{
            marginTop: 4,
            background: 'none',
            border: 'none',
            color: 'var(--accent)',
            fontSize: '0.82rem',
            cursor: 'pointer',
            padding: 0,
            textDecoration: 'underline',
          }}
        >
          {cta.label}
        </button>
      )}
    </div>
  );
}

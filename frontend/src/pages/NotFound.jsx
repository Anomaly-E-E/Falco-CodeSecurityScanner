import React from 'react';
import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexDirection: 'column',
      gap: 14,
      padding: 24,
    }}>
      <p style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '4rem',
        color: 'var(--text-muted)',
        fontWeight: 500,
        letterSpacing: '0.05em',
      }}>
        404
      </p>
      <p style={{
        color: 'var(--text-secondary)',
        fontSize: '0.95rem',
        fontFamily: 'var(--font-serif)',
      }}>
        Page not found.
      </p>
      <Link to="/dashboard" style={{
        marginTop: 6,
        color: 'var(--accent)',
        fontSize: '0.85rem',
        fontFamily: 'var(--font-mono)',
      }}>
        Go to dashboard →
      </Link>
    </div>
  );
}

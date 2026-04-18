import React from 'react';

export function AuthLogo() {
  return (
    <div style={{ textAlign: 'center', marginBottom: 28 }}>
      <span style={{ color: 'var(--accent)', fontSize: '0.9rem', marginRight: 7 }}>◆</span>
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontWeight: 500,
        fontSize: '1.1rem',
        color: 'var(--text-primary)',
        letterSpacing: '0.06em',
      }}>
        falco
      </span>
      <p style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '0.7rem',
        color: 'var(--text-muted)',
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        marginTop: 6,
      }}>
        security scanner
      </p>
    </div>
  );
}

export const authWrap = {
  minHeight: '100vh',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: 24,
  background: 'var(--bg-primary)',
};

export const authInner = { width: '100%', maxWidth: 400 };
export const authCard  = { padding: '32px 28px' };
export const authFooter = {
  textAlign: 'center',
  marginTop: 22,
  fontSize: '0.82rem',
  color: 'var(--text-muted)',
};

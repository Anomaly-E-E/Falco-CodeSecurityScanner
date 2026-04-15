import React from 'react';

export function AuthLogo() {
  return (
    <div style={{ textAlign: 'center', marginBottom: 20 }}>
      <span style={{ color: 'var(--accent)', fontSize: '0.8rem', marginRight: 6 }}>◆</span>
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '1rem',
        color: 'var(--text-primary)',
        fontWeight: 500,
      }}>
        falco
      </span>
    </div>
  );
}

export const authWrap = {
  minHeight: '100vh',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: 20,
  background: 'var(--bg-primary)',
};

export const authInner = { width: '100%', maxWidth: 380 };
export const authCard  = { padding: '28px 24px' };
export const authFooter = {
  textAlign: 'center',
  marginTop: 18,
  fontSize: '0.8rem',
  color: 'var(--text-muted)',
};

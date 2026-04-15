import React from 'react';
import { Link, Outlet, useNavigate } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import CreditsBadge from './CreditsBadge';

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate('/login');
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <nav style={{
        background: 'var(--bg-primary)',
        borderBottom: '1px solid var(--border)',
        padding: '0 24px',
        height: 52,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 20,
      }}>
        <Link
          to="/dashboard"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            textDecoration: 'none',
          }}
        >
          <span style={{ color: 'var(--accent)', fontSize: '0.75rem', lineHeight: 1 }}>◆</span>
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontWeight: 500,
            fontSize: '0.9rem',
            color: 'var(--text-primary)',
            letterSpacing: '0.02em',
          }}>
            falco
          </span>
        </Link>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <CreditsBadge credits={user?.credits ?? null} />
          <span style={{
            color: 'var(--text-muted)',
            fontSize: '0.78rem',
            fontFamily: 'var(--font-mono)',
            maxWidth: 200,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}>
            {user?.email}
          </span>
          <button
            onClick={handleLogout}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              fontSize: '0.78rem',
              cursor: 'pointer',
              padding: 0,
              transition: 'color 0.12s',
            }}
            onMouseEnter={e => e.target.style.color = 'var(--text-primary)'}
            onMouseLeave={e => e.target.style.color = 'var(--text-muted)'}
          >
            sign out
          </button>
        </div>
      </nav>

      <main style={{ flex: 1 }}>
        <Outlet />
      </main>
    </div>
  );
}

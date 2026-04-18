import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import api from '../api/client';
import { AuthLogo, authWrap, authInner, authCard } from '../components/AuthLayout';

export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get('token');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);

  if (!token) {
    return (
      <div style={authWrap}>
        <div className="card" style={{ ...authCard, maxWidth: 400, width: '100%' }}>
          <p style={{ color: 'var(--danger)', fontSize: '0.875rem' }}>
            invalid reset link. <Link to="/forgot-password">request a new one</Link>.
          </p>
        </div>
      </div>
    );
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (password !== confirm) { setError('passwords do not match'); return; }
    if (password.length < 8) { setError('password must be at least 8 characters'); return; }
    setLoading(true);
    const { ok, error: err } = await api.post('/auth/reset-password', { token, newPassword: password });
    if (ok) setDone(true);
    else { setError(err); setLoading(false); }
  }

  return (
    <div style={authWrap}>
      <div style={authInner}>
        <AuthLogo />
        <div className="card" style={authCard}>
          {done ? (
            <>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: 16 }}>
                password updated.
              </p>
              <Link to="/login" className="btn btn-primary" style={{ display: 'flex', justifyContent: 'center' }}>
                sign in
              </Link>
            </>
          ) : (
            <>
              {error && <div className="error-msg">{error}</div>}
              <form onSubmit={handleSubmit}>
                <div className="form-group">
                  <label className="form-label">new password</label>
                  <input type="password" className="form-input" value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="min. 8 chars, uppercase, number" required autoFocus />
                </div>
                <div className="form-group">
                  <label className="form-label">confirm password</label>
                  <input type="password" className="form-input" value={confirm}
                    onChange={e => setConfirm(e.target.value)}
                    placeholder="same as above" required />
                </div>
                <button type="submit" className="btn btn-primary"
                  disabled={loading} style={{ width: '100%' }}>
                  {loading ? 'saving...' : 'update password'}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

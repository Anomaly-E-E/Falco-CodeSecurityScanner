import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import { AuthLogo, authWrap, authInner, authCard, authFooter } from '../components/AuthLayout';

export default function Register() {
  const { register } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (password !== confirm) { setError('passwords do not match'); return; }
    if (password.length < 8)  { setError('password must be at least 8 characters'); return; }
    setLoading(true);
    const result = await register(email, password);
    if (result.ok) setDone(true);
    else { setError(result.error); setLoading(false); }
  }

  if (done) {
    return (
      <div style={authWrap}>
        <div style={authInner}>
          <AuthLogo />
          <div className="card" style={authCard}>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>
              check your email — we sent a verification link to{' '}
              <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{email}</span>.
            </p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              already verified? <Link to="/login">sign in</Link>
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={authWrap}>
      <div style={authInner}>
        <AuthLogo />
        <div className="card" style={authCard}>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 16 }}>
            10 free credits on signup
          </p>
          {error && <div className="error-msg">{error}</div>}
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">email</label>
              <input type="email" className="form-input" value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com" required autoFocus />
            </div>
            <div className="form-group">
              <label className="form-label">password</label>
              <input type="password" className="form-input" value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="min. 8 chars, uppercase, number" required />
            </div>
            <div className="form-group">
              <label className="form-label">confirm password</label>
              <input type="password" className="form-input" value={confirm}
                onChange={e => setConfirm(e.target.value)}
                placeholder="same as above" required />
            </div>
            <button type="submit" className="btn btn-primary"
              disabled={loading} style={{ width: '100%', marginTop: 6 }}>
              {loading ? 'creating account...' : 'create account'}
            </button>
          </form>
          <p style={authFooter}>
            have an account? <Link to="/login">sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

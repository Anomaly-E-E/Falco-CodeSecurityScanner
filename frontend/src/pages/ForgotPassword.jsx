import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client';
import { AuthLogo, authWrap, authInner, authCard, authFooter } from '../components/AuthLayout';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    const { ok } = await api.post('/auth/forgot-password', { email });
    setLoading(false);
    if (ok) {
      setSent(true);
    } else {
      setError('something went wrong — please try again');
    }
  }

  return (
    <div style={authWrap}>
      <div style={authInner}>
        <AuthLogo />
        <div className="card" style={authCard}>
          {sent ? (
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
              if that email is registered, check your inbox for a reset link.
            </p>
          ) : (
            <form onSubmit={handleSubmit}>
              {error && <div className="error-msg">{error}</div>}
              <div className="form-group">
                <label className="form-label">email</label>
                <input type="email" className="form-input" value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com" required autoFocus />
              </div>
              <button type="submit" className="btn btn-primary"
                disabled={loading} style={{ width: '100%' }}>
                {loading ? 'sending...' : 'send reset link'}
              </button>
            </form>
          )}
          <p style={authFooter}>
            <Link to="/login">back to sign in</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

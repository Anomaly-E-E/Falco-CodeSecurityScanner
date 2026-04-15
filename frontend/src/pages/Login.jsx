import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import { AuthLogo, authWrap, authInner, authCard, authFooter } from '../components/AuthLayout';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    const result = await login(email, password);
    if (result.ok) {
      navigate('/dashboard');
    } else {
      setError(result.error);
      setLoading(false);
    }
  }

  return (
    <div style={authWrap}>
      <div style={authInner}>
        <AuthLogo />
        <div className="card" style={authCard}>
          {error && <div className="error-msg">{error}</div>}
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">email</label>
              <input type="email" className="form-input" value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com" required autoFocus />
            </div>
            <div className="form-group">
              <label className="form-label">
                password
                <Link to="/forgot-password" style={{ fontSize: '0.75rem' }}>forgot it?</Link>
              </label>
              <input type="password" className="form-input" value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••" required />
            </div>
            <button type="submit" className="btn btn-primary"
              disabled={loading} style={{ width: '100%', marginTop: 6 }}>
              {loading ? 'signing in...' : 'sign in'}
            </button>
          </form>
          <p style={authFooter}>
            no account? <Link to="/register">create one</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

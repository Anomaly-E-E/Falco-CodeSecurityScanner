import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import api from '../api/client';
import LoadingSpinner from '../components/LoadingSpinner';
import { AuthLogo, authWrap, authInner, authCard } from '../components/AuthLayout';

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const [status, setStatus] = useState('verifying');
  const [message, setMessage] = useState('');

  const token = params.get('token');

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setMessage('no verification token found in the URL.');
      return;
    }
    api.post('/auth/verify-email', { token }).then(({ ok, data, error }) => {
      if (ok) { setStatus('success'); setMessage(data.message); }
      else    { setStatus('error');   setMessage(error); }
    });
  }, [token]);

  return (
    <div style={authWrap}>
      <div style={authInner}>
        <AuthLogo />
        <div className="card" style={{ ...authCard, textAlign: 'center' }}>
          {status === 'verifying' && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
              <LoadingSpinner size={20} />
              <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>verifying...</p>
            </div>
          )}

          {status === 'success' && (
            <>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--success)', marginBottom: 10 }}>
                [verified]
              </p>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: 18, lineHeight: 1.6 }}>
                {message}
              </p>
              <Link to="/login" className="btn btn-primary" style={{ display: 'flex', justifyContent: 'center' }}>
                sign in
              </Link>
            </>
          )}

          {status === 'error' && (
            <>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--danger)', marginBottom: 10 }}>
                [failed]
              </p>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: 18, lineHeight: 1.6 }}>
                {message}
              </p>
              <Link to="/login" style={{ fontSize: '0.85rem' }}>back to sign in</Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

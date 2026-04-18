import React, { createContext, useState, useEffect, useCallback } from 'react';
import api, { getToken, setToken, clearToken } from '../api/client';

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // on mount, validate the stored token by hitting /auth/me
  useEffect(() => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }

    api.get('/auth/me').then(({ ok, data }) => {
      if (ok) {
        setUser(data);
      } else {
        clearToken();
      }
      setLoading(false);
    });
  }, []);

  const login = useCallback(async (email, password) => {
    const { ok, data, error } = await api.post('/auth/login', { email, password });
    if (!ok) return { ok: false, error };

    setToken(data.token);
    setUser(data.user);
    return { ok: true };
  }, []);

  const register = useCallback(async (email, password) => {
    const { ok, data, error } = await api.post('/auth/register', { email, password });
    if (!ok) return { ok: false, error };
    return { ok: true, message: data.message };
  }, []);

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
  }, []);

  // called after a scan completes to keep the credit count in sync
  const refreshCredits = useCallback(async () => {
    const { ok, data } = await api.get('/auth/me');
    if (ok && data) {
      setUser(prev => prev ? { ...prev, credits: data.credits } : data);
    }
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshCredits }}>
      {children}
    </AuthContext.Provider>
  );
}

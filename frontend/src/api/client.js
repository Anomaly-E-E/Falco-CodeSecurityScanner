const TOKEN_KEY = 'falco_token';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function request(endpoint, options = {}) {
  const token = getToken();

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers
  };

  try {
    const res = await fetch(`/api${endpoint}`, {
      ...options,
      headers
    });

    let data;
    try {
      data = await res.json();
    } catch {
      data = {};
    }

    if (res.status === 401) {
      clearToken();
      window.location.href = '/login';
      return { ok: false, error: 'Session expired. Please log in again.' };
    }

    if (!res.ok) {
      return { ok: false, error: data.error || 'Something went wrong' };
    }

    return { ok: true, data };
  } catch {
    return { ok: false, error: 'Network error. Check your connection.' };
  }
}

const api = {
  get: (endpoint) => request(endpoint, { method: 'GET' }),
  post: (endpoint, body) => request(endpoint, { method: 'POST', body: JSON.stringify(body) }),
  put: (endpoint, body) => request(endpoint, { method: 'PUT', body: JSON.stringify(body) }),
  delete: (endpoint) => request(endpoint, { method: 'DELETE' })
};

export default api;

(() => {
  'use strict';
  const KEY = 'ndd_portal_session';
  const cfg = () => window.NDD_PORTAL_CONFIG || {};
  const base = () => String(cfg().apiBaseUrl || '').replace(/\/$/, '');

  function session() {
    try { return JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch { return null; }
  }
  function save(value) { sessionStorage.setItem(KEY, JSON.stringify(value)); }
  function clear() { sessionStorage.removeItem(KEY); }
  function token() { return session()?.token || ''; }
  function user() { return session()?.user || null; }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!headers.has('Content-Type') && options.body != null) headers.set('Content-Type', 'application/json');
    if (token()) headers.set('Authorization', `Bearer ${token()}`);
    const response = await fetch(`${base()}${path}`, { ...options, headers });
    let data = null;
    try { data = await response.json(); } catch { data = {}; }
    if (response.status === 401) clear();
    if (!response.ok) {
      const error = new Error(data?.error || `HTTP_${response.status}`);
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  }

  async function login(username, password) {
    const data = await request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    save({ token: data.token, user: data.user, expiresInHours: data.expiresInHours, createdAt: Date.now() });
    return data.user;
  }

  async function logout() {
    try { if (token()) await request('/auth/logout', { method: 'POST' }); } catch (_) {}
    clear();
    location.href = cfg().loginPage || 'login.html';
  }

  async function requireAuth(requiredRole) {
    if (!token()) { location.replace(cfg().loginPage || 'login.html'); return null; }
    try {
      const data = await request('/auth/me');
      const normalized = {
        id: data.user.id,
        username: data.user.username,
        displayName: data.user.display_name || data.user.displayName,
        email: data.user.email,
        role: data.user.role
      };
      const current = session() || {};
      save({ ...current, user: normalized });
      if (requiredRole && normalized.role !== requiredRole) {
        location.replace(cfg().portalPage || 'index.html');
        return null;
      }
      return normalized;
    } catch (_) {
      clear(); location.replace(cfg().loginPage || 'login.html'); return null;
    }
  }

  async function audit(actionType, details = {}) {
    return request('/audit/actions', {
      method: 'POST',
      body: JSON.stringify({ actionType, pagePath: location.pathname, ...details })
    });
  }

  async function saveDocument(documentType, product, snapshot, details = {}) {
    return request('/audit/documents', {
      method: 'POST',
      body: JSON.stringify({ documentType, product, snapshot, ...details })
    });
  }

  window.NDDAuth = Object.freeze({ session, user, token, request, login, logout, requireAuth, audit, saveDocument });
})();

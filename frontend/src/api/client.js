const DEFAULT_BASE_URL = 'http://localhost:8000';
const TOKEN_KEY = 'ids_auth_token';

function getBaseUrl() {
  return localStorage.getItem('ids_api_base_url') || DEFAULT_BASE_URL;
}

export function setBaseUrl(url) {
  localStorage.setItem('ids_api_base_url', url);
}

export function getApiBaseUrl() {
  return getBaseUrl();
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

class ApiError extends Error {
  constructor(message, status, detail) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function request(path, { method = 'GET', params, body } = {}) {
  const base = getBaseUrl().replace(/\/$/, '');
  const url = new URL(`${base}${path}`);

  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, value);
      }
    });
  }

  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(url.toString(), {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    throw new ApiError(
      `Can't reach the IDS backend at ${base}. Check that the server is running and the API URL is correct.`,
      0,
      null
    );
  }

  if (res.status === 401) {
    const wasLoggedIn = !!token;
    clearToken();
    // Don't fire for the login attempt itself (no token was set yet) -
    // only when a previously-authenticated session gets rejected.
    if (wasLoggedIn) {
      window.dispatchEvent(new CustomEvent('auth:unauthorized'));
    }
  }

  if (res.status === 204) {
    return null;
  }

  const isJson = res.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await res.json().catch(() => null) : await res.text();

  if (!res.ok) {
    const detail = isJson ? data?.detail : data;
    throw new ApiError(
      typeof detail === 'string' ? detail : `Request failed (${res.status})`,
      res.status,
      detail
    );
  }

  return data;
}

export const api = {
  get: (path, params) => request(path, { method: 'GET', params }),
  post: (path, body, params) => request(path, { method: 'POST', body, params }),
  put: (path, body) => request(path, { method: 'PUT', body }),
  patch: (path, body) => request(path, { method: 'PATCH', body }),
  delete: (path) => request(path, { method: 'DELETE' }),
};

export { ApiError };

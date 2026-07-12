import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authApi } from '../api/auth';
import { getToken, setToken as persistToken, clearToken } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setTokenState] = useState(() => getToken());
  const [user, setUser] = useState(null);
  // "checking" covers the initial mount-time validation of a token that was
  // already in localStorage, so ProtectedRoute doesn't flash the login page
  // before we know whether the stored session is still valid.
  const [checking, setChecking] = useState(true);

  const logout = useCallback(() => {
    clearToken();
    setTokenState(null);
    setUser(null);
  }, []);

  const login = useCallback(async (username, password) => {
    const { access_token } = await authApi.login(username, password);
    persistToken(access_token);
    setTokenState(access_token);
    const me = await authApi.me();
    setUser(me);
    return me;
  }, []);

  // If any request comes back 401 (expired/invalid token), the client
  // dispatches this event - drop the session so ProtectedRoute redirects.
  useEffect(() => {
    window.addEventListener('auth:unauthorized', logout);
    return () => window.removeEventListener('auth:unauthorized', logout);
  }, [logout]);

  useEffect(() => {
    if (!token) {
      setChecking(false);
      return;
    }
    authApi
      .me()
      .then(setUser)
      .catch(() => logout())
      .finally(() => setChecking(false));
    // Only re-validate on mount; login()/logout() manage state after that.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!token,
        checking,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}

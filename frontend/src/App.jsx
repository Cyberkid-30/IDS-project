import { Routes, Route, Navigate } from 'react-router-dom';
import NavRail from './components/NavRail';
import PulseStrip from './components/PulseStrip';
import ConnectionBanner from './components/ConnectionBanner';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Signatures from './pages/Signatures';
import SystemPage from './pages/SystemPage';
import { usePolling } from './hooks/usePolling';
import { systemApi } from './api/system';
import { useAuth } from './context/AuthContext';

function Console() {
  const { data: status, error } = usePolling(() => systemApi.status(), 4000);

  const running = status?.detection_running ?? false;
  const packetsPerSecond =
    running && status?.uptime_seconds
      ? status.packets_processed / Math.max(status.uptime_seconds, 1)
      : 0;

  return (
    <div className="app-shell">
      <NavRail />
      <div className="app-main">
        <PulseStrip running={running} packetsPerSecond={packetsPerSecond} />
        {error && <ConnectionBanner message={error.message} />}
        <div className="app-content">
          <Routes>
            <Route path="/" element={<Dashboard status={status} />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/signatures" element={<Signatures />} />
            <Route path="/system" element={<SystemPage status={status} />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const { isAuthenticated, checking } = useAuth();

  return (
    <Routes>
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <Login />}
      />
      <Route
        path="/*"
        element={
          checking ? (
            <div className="auth-checking mono">Checking session…</div>
          ) : (
            <ProtectedRoute>
              <Console />
            </ProtectedRoute>
          )
        }
      />
    </Routes>
  );
}

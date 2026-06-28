import { useEffect, useState } from 'react';
import Panel from '../components/Panel';
import { systemApi } from '../api/system';
import { alertsApi } from '../api/alerts';
import { getApiBaseUrl, setBaseUrl } from '../api/client';
import { formatDuration, formatNumber, formatTimestamp } from '../api/format';

export default function SystemPage({ status }) {
  const [network, setNetwork] = useState(null);
  const [config, setConfig] = useState(null);
  const [error, setError] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [apiUrl, setApiUrl] = useState(getApiBaseUrl());
  const [savedNote, setSavedNote] = useState(false);
  const [cleanupDays, setCleanupDays] = useState(30);
  const [cleanupResult, setCleanupResult] = useState(null);
  const [cleanupBusy, setCleanupBusy] = useState(false);

  useEffect(() => {
    Promise.all([systemApi.network(), systemApi.config()])
      .then(([n, c]) => { setNetwork(n); setConfig(c); })
      .catch((err) => setError(err));
  }, []);

  async function handleToggleDetection() {
    setBusy(true);
    setActionError(null);
    try {
      if (status?.detection_running) {
        await systemApi.stopDetection();
      } else {
        await systemApi.startDetection();
      }
    } catch (err) {
      setActionError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleReload() {
    setBusy(true);
    setActionError(null);
    try {
      await systemApi.reloadSignatures();
    } catch (err) {
      setActionError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function handleSaveUrl(e) {
    e.preventDefault();
    setBaseUrl(apiUrl.trim());
    setSavedNote(true);
    setTimeout(() => window.location.reload(), 600);
  }

  async function handleCleanup() {
    setCleanupBusy(true);
    setCleanupResult(null);
    try {
      const res = await alertsApi.cleanup(cleanupDays);
      setCleanupResult(res);
    } catch (err) {
      setActionError(err.message);
    } finally {
      setCleanupBusy(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-header__title">System</h1>
          <p className="page-header__subtitle">Detection engine control, network configuration, and connection settings.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Panel
          title="Detection engine"
          action={
            <button className="btn btn--sm btn--ghost" disabled={busy} onClick={handleReload}>
              Reload signatures
            </button>
          }
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <div className="mono" style={{ fontSize: 13, fontWeight: 600, color: status?.detection_running ? 'var(--signal-active)' : 'var(--text-tertiary)' }}>
                {status?.detection_running ? 'RUNNING' : 'STOPPED'}
              </div>
              <div className="cell-muted" style={{ fontSize: 11.5, marginTop: 2 }}>
                {status?.has_capture_permissions ? 'Capture permissions OK' : 'No packet capture permissions — see README'}
              </div>
            </div>
            <button
              className={`btn ${status?.detection_running ? 'btn--danger' : 'btn--primary'}`}
              disabled={busy}
              onClick={handleToggleDetection}
            >
              {busy ? 'Working…' : status?.detection_running ? 'Stop detection' : 'Start detection'}
            </button>
          </div>

          {actionError && <div className="field__error" style={{ marginBottom: 12 }}>{actionError}</div>}

          <DetailGrid
            rows={[
              ['Interface', status?.network_interface],
              ['Capture filter', status?.capture_filter],
              ['Signatures loaded', formatNumber(status?.signatures_loaded)],
              ['Packets processed', formatNumber(status?.packets_processed)],
              ['Alerts generated', formatNumber(status?.alerts_generated)],
              ['Uptime', status ? formatDuration(status.uptime_seconds) : '—'],
              ['Started', status?.start_time ? formatTimestamp(status.start_time) : '—'],
            ]}
          />
        </Panel>

        <Panel title="Network">
          {error ? (
            <div className="field__error">{error.message}</div>
          ) : !network ? (
            <div className="skeleton" style={{ height: 120 }} />
          ) : (
            <>
              <DetailGrid
                rows={[
                  ['Configured interface', network.current_interface],
                  ['Capture filter (BPF)', network.capture_filter],
                  ['Root / capture privileges', network.has_root_privileges ? 'Yes' : 'No'],
                ]}
              />
              <div style={{ marginTop: 16 }}>
                <div className="field__label" style={{ marginBottom: 8 }}>Available interfaces</div>
                {network.available_interfaces?.length ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {network.available_interfaces.map((iface) => (
                      <span key={iface} className="badge mono" style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-bright)' }}>
                        {iface}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="cell-muted" style={{ fontSize: 12 }}>None detected</span>
                )}
              </div>
            </>
          )}
        </Panel>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Panel title="Configuration">
          {!config ? (
            <div className="skeleton" style={{ height: 160 }} />
          ) : (
            <DetailGrid
              rows={[
                ['App name', config.app_name],
                ['Version', config.version],
                ['Debug mode', config.debug ? 'On' : 'Off'],
                ['Log level', config.log_level],
                ['Alert retention', `${config.alert_retention_days} days`],
                ['API prefix', config.api_prefix],
                ['Capture timeout', `${config.capture_timeout}s`],
              ]}
            />
          )}
        </Panel>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Panel title="Backend connection">
            <form onSubmit={handleSaveUrl}>
              <div className="field">
                <label className="field__label">API base URL</label>
                <input
                  className="input mono"
                  value={apiUrl}
                  onChange={(e) => { setApiUrl(e.target.value); setSavedNote(false); }}
                  placeholder="http://localhost:8000"
                />
                <span className="field__hint">Where this dashboard sends requests. Saved locally in your browser.</span>
              </div>
              <div className="form-actions" style={{ borderTop: 'none', paddingTop: 12, marginTop: 12 }}>
                {savedNote && <span className="cell-muted" style={{ fontSize: 11.5, alignSelf: 'center' }}>Saved — reloading…</span>}
                <button type="submit" className="btn btn--primary btn--sm">Save & reload</button>
              </div>
            </form>
          </Panel>

          <Panel title="Alert cleanup">
            <div className="field">
              <label className="field__label">Delete alerts older than</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="number"
                  className="input"
                  min={1}
                  max={365}
                  value={cleanupDays}
                  onChange={(e) => setCleanupDays(Number(e.target.value))}
                  style={{ width: 100 }}
                />
                <span style={{ alignSelf: 'center', color: 'var(--text-secondary)', fontSize: 13 }}>days</span>
                <button className="btn btn--ghost btn--sm" style={{ marginLeft: 'auto' }} disabled={cleanupBusy} onClick={handleCleanup}>
                  {cleanupBusy ? 'Cleaning…' : 'Run cleanup'}
                </button>
              </div>
              {cleanupResult && (
                <span className="field__hint">Deleted {cleanupResult.deleted} alert(s) older than {cleanupResult.days_threshold} days.</span>
              )}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

function DetailGrid({ rows }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
      {rows.map(([label, value]) => (
        <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
          <span className="cell-muted" style={{ fontSize: 12 }}>{label}</span>
          <span className="mono" style={{ fontSize: 12.5, textAlign: 'right' }}>{value ?? '—'}</span>
        </div>
      ))}
    </div>
  );
}

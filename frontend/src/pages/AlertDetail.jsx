import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import Panel from '../components/Panel';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import { alertsApi } from '../api/alerts';
import { formatTimestamp } from '../api/format';

const STATUSES = ['new', 'acknowledged', 'resolved', 'false_positive'];

export default function AlertDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await alertsApi.get(id);
      setAlert(data);
      setError(null);
    } catch (err) {
      setError(err);
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleStatusChange(newStatus) {
    setBusy(true);
    try {
      const updated = await alertsApi.updateStatus(id, newStatus);
      setAlert(updated);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    if (!window.confirm('Delete this alert? This cannot be undone.')) return;
    setBusy(true);
    try {
      await alertsApi.remove(id);
      navigate('/alerts');
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  if (error && !alert) {
    return (
      <>
        <Link to="/alerts" className="btn btn--ghost btn--sm" style={{ marginBottom: 16, display: 'inline-flex' }}>← Back to alerts</Link>
        <Panel><div className="field__error">{error.message}</div></Panel>
      </>
    );
  }

  if (!alert) {
    return (
      <>
        <Link to="/alerts" className="btn btn--ghost btn--sm" style={{ marginBottom: 16, display: 'inline-flex' }}>← Back to alerts</Link>
        <div className="skeleton" style={{ height: 200 }} />
      </>
    );
  }

  return (
    <>
      <Link to="/alerts" className="btn btn--ghost btn--sm" style={{ marginBottom: 16, display: 'inline-flex' }}>← Back to alerts</Link>

      <div className="page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
          </div>
          <h1 className="page-header__title">{alert.signature_name || `Signature #${alert.signature_id}`}</h1>
          <p className="page-header__subtitle">Alert #{alert.id} · triggered {formatTimestamp(alert.timestamp)}</p>
        </div>
        <div className="page-header__actions">
          <select
            className="select"
            value={alert.status}
            disabled={busy}
            onChange={(e) => handleStatusChange(e.target.value)}
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s.replace('_', ' ')}</option>
            ))}
          </select>
          <button className="btn btn--danger btn--sm" disabled={busy} onClick={handleDelete}>Delete alert</button>
        </div>
      </div>

      {error && <div className="field__error" style={{ marginBottom: 12 }}>{error.message}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Panel title="Connection details">
          <DetailGrid
            rows={[
              ['Source', `${alert.source_ip}${alert.source_port ? `:${alert.source_port}` : ''}`],
              ['Destination', `${alert.dest_ip}${alert.dest_port ? `:${alert.dest_port}` : ''}`],
              ['Protocol', alert.protocol?.toUpperCase()],
              ['Packet count', alert.packet_count],
            ]}
          />
        </Panel>

        <Panel title="Signature">
          <DetailGrid
            rows={[
              ['Signature ID', alert.signature_id],
              ['Severity', alert.severity],
              ['Triggered', formatTimestamp(alert.timestamp)],
              ['Recorded', formatTimestamp(alert.created_at)],
            ]}
          />
        </Panel>
      </div>

      {alert.payload_snippet && (
        <div style={{ marginTop: 16 }}>
          <Panel title="Payload snippet">
            <pre className="mono" style={{
              margin: 0,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              fontSize: 12.5,
              color: 'var(--text-primary)',
              background: 'var(--bg-inset)',
              padding: 12,
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)',
            }}>
              {alert.payload_snippet}
            </pre>
          </Panel>
        </div>
      )}
    </>
  );
}

function DetailGrid({ rows }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {rows.map(([label, value]) => (
        <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
          <span className="cell-muted" style={{ fontSize: 12 }}>{label}</span>
          <span className="mono" style={{ fontSize: 12.5, textAlign: 'right' }}>{value ?? '—'}</span>
        </div>
      ))}
    </div>
  );
}

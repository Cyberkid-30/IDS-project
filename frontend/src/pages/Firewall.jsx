import { useState } from 'react';
import Panel from '../components/Panel';
import EmptyState from '../components/EmptyState';
import Modal from '../components/Modal';
import { firewallApi } from '../api/firewall';
import { formatTimestamp, formatRelativeTime } from '../api/format';
import { usePolling } from '../hooks/usePolling';

export default function Firewall() {
  const { data: result, error, loading, refresh } = usePolling(() => firewallApi.list(), 5000);
  const [blocking, setBlocking] = useState(false);
  const [unblockTarget, setUnblockTarget] = useState(null);
  const [busyIp, setBusyIp] = useState(null);
  const [actionError, setActionError] = useState(null);

  async function handleBlock(data) {
    await firewallApi.block(data);
    setBlocking(false);
    await refresh();
  }

  async function handleUnblock(ip) {
    setBusyIp(ip);
    setActionError(null);
    try {
      await firewallApi.unblock(ip);
      setUnblockTarget(null);
      await refresh();
    } catch (err) {
      setActionError(err);
    } finally {
      setBusyIp(null);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-header__title">Firewall</h1>
          <p className="page-header__subtitle">
            {result
              ? `${result.total.toLocaleString()} IP${result.total === 1 ? '' : 's'} currently blocked via ufw`
              : 'Loading blocked IPs…'}
          </p>
        </div>
        <div className="page-header__actions">
          <button className="btn btn--primary" onClick={() => setBlocking(true)}>+ Block IP</button>
        </div>
      </div>

      {error && <div className="field__error" style={{ marginBottom: 12 }}>{error.message}</div>}
      {actionError && <div className="field__error" style={{ marginBottom: 12 }}>{actionError.message}</div>}

      <Panel>
        {loading && !result ? (
          <SkeletonTable />
        ) : !result || result.blocked_ips.length === 0 ? (
          <EmptyState
            title="No IPs blocked"
            body="Manually block a suspicious IP here, or wait for the detection engine to auto-block a critical-severity source."
            action={<button className="btn btn--primary btn--sm" onClick={() => setBlocking(true)}>+ Block IP</button>}
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>IP address</th>
                  <th>Reason</th>
                  <th>Alerts</th>
                  <th>Blocked</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {result.blocked_ips.map((b) => (
                  <tr key={b.id}>
                    <td className="mono" style={{ fontWeight: 600 }}>{b.ip_address}</td>
                    <td className="cell-muted col-wrap">{b.reason || '—'}</td>
                    <td className="mono">{b.alert_count}</td>
                    <td className="cell-muted" title={formatTimestamp(b.blocked_at)}>{formatRelativeTime(b.blocked_at)}</td>
                    <td>
                      <button
                        className="btn btn--ghost btn--sm"
                        disabled={busyIp === b.ip_address}
                        onClick={() => setUnblockTarget(b)}
                      >
                        {busyIp === b.ip_address ? 'Unblocking…' : 'Unblock'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {blocking && (
        <Modal title="Block an IP address" onClose={() => setBlocking(false)}>
          <BlockForm onSubmit={handleBlock} onCancel={() => setBlocking(false)} />
        </Modal>
      )}

      {unblockTarget && (
        <Modal title="Unblock IP" onClose={() => setUnblockTarget(null)}>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.6 }}>
            Remove the ufw deny rule for{' '}
            <strong className="mono" style={{ color: 'var(--text-primary)' }}>{unblockTarget.ip_address}</strong>?
            Traffic from this IP will be allowed through again immediately.
          </p>
          <div className="form-actions">
            <button className="btn btn--ghost" onClick={() => setUnblockTarget(null)}>Cancel</button>
            <button
              className="btn btn--danger"
              disabled={busyIp === unblockTarget.ip_address}
              onClick={() => handleUnblock(unblockTarget.ip_address)}
            >
              {busyIp === unblockTarget.ip_address ? 'Unblocking…' : 'Unblock IP'}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function BlockForm({ onSubmit, onCancel }) {
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      await onSubmit({ ip_address: ip.trim(), reason: reason.trim() || undefined });
    } catch (err) {
      setError(err.detail || err.message || 'Could not block IP.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="field" style={{ marginBottom: 12 }}>
        <label className="field__label">IP address</label>
        <input
          className="input mono"
          required
          minLength={7}
          maxLength={50}
          autoFocus
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="e.g. 203.0.113.42"
        />
        <span className="field__hint">Adds a ufw deny rule for this address and records it in the database.</span>
      </div>

      <div className="field">
        <label className="field__label">Reason (optional)</label>
        <input
          className="input"
          maxLength={500}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. Repeated port scan"
        />
      </div>

      {error && <div className="field__error" style={{ marginTop: 12 }}>{error}</div>}

      <div className="form-actions">
        <button type="button" className="btn btn--ghost" onClick={onCancel} disabled={saving}>Cancel</button>
        <button type="submit" className="btn btn--primary" disabled={saving || !ip.trim()}>
          {saving ? 'Blocking…' : 'Block IP'}
        </button>
      </div>
    </form>
  );
}

function SkeletonTable() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="skeleton" style={{ height: 18, width: `${90 - i * 6}%` }} />
      ))}
    </div>
  );
}

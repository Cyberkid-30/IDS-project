import { useCallback, useEffect, useState } from 'react';
import Panel from '../components/Panel';
import EmptyState from '../components/EmptyState';
import Modal from '../components/Modal';
import { firewallApi } from '../api/firewall';
import { formatTimestamp, formatRelativeTime } from '../api/format';

const EMPTY_FORM = { ip_address: '', reason: '' };

export default function Firewall() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busyIp, setBusyIp] = useState(null);
  const [blocking, setBlocking] = useState(null); // null = closed, {} = open
  const [unblockTarget, setUnblockTarget] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await firewallApi.list();
      setResult(data);
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleBlockSubmit(form) {
    await firewallApi.block({
      ip_address: form.ip_address.trim(),
      reason: form.reason.trim() || null,
    });
    setBlocking(null);
    await load();
  }

  async function handleUnblock(entry) {
    setBusyIp(entry.ip_address);
    try {
      await firewallApi.unblock(entry.ip_address);
      setUnblockTarget(null);
      await load();
    } catch (err) {
      setError(err);
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
              ? `${result.total.toLocaleString()} IP${result.total === 1 ? '' : 's'} currently blocked`
              : 'Loading blocked IPs…'}
          </p>
        </div>
        <div className="page-header__actions">
          <button className="btn btn--primary" onClick={() => setBlocking({})}>+ Block IP</button>
        </div>
      </div>

      <p style={{ color: 'var(--text-secondary)', fontSize: 12.5, lineHeight: 1.6, marginBottom: 16, maxWidth: 640 }}>
        Blocks are applied via <span className="mono">ufw</span>. Critical-severity alerts trigger an automatic
        block; you can also block or unblock an IP by hand below.
      </p>

      {error && <div className="field__error" style={{ marginBottom: 12 }}>{error.message}</div>}

      <Panel>
        {loading && !result ? (
          <SkeletonTable />
        ) : !result || result.blocked_ips.length === 0 ? (
          <EmptyState
            title="No IPs blocked"
            body="Blocked IPs — whether added automatically from critical alerts or blocked manually — will show up here."
            action={<button className="btn btn--primary btn--sm" onClick={() => setBlocking({})}>+ Block IP</button>}
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
                {result.blocked_ips.map((entry) => (
                  <tr key={entry.id}>
                    <td className="mono" style={{ fontWeight: 600 }}>{entry.ip_address}</td>
                    <td className="cell-muted col-wrap">{entry.reason || '—'}</td>
                    <td className="mono cell-muted">{entry.alert_count}</td>
                    <td className="cell-muted" title={formatTimestamp(entry.blocked_at)}>
                      {formatRelativeTime(entry.blocked_at)}
                    </td>
                    <td>
                      <button className="btn btn--ghost btn--sm" onClick={() => setUnblockTarget(entry)}>
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {blocking !== null && (
        <Modal title="Block an IP address" onClose={() => setBlocking(null)}>
          <BlockForm onSubmit={handleBlockSubmit} onCancel={() => setBlocking(null)} />
        </Modal>
      )}

      {unblockTarget && (
        <Modal title="Unblock IP" onClose={() => setUnblockTarget(null)}>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.6 }}>
            Remove the ufw block for{' '}
            <strong className="mono" style={{ color: 'var(--text-primary)' }}>{unblockTarget.ip_address}</strong>?
            Traffic from this address will be allowed through again.
          </p>
          <div className="form-actions">
            <button className="btn btn--ghost" onClick={() => setUnblockTarget(null)}>Cancel</button>
            <button
              className="btn btn--danger"
              disabled={busyIp === unblockTarget.ip_address}
              onClick={() => handleUnblock(unblockTarget)}
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
  const [form, setForm] = useState(EMPTY_FORM);
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSubmit(form);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div className="form-grid">
        <div className="field form-grid--full">
          <label className="field__label">IP address</label>
          <input
            className="input mono"
            required
            minLength={7}
            maxLength={50}
            value={form.ip_address}
            onChange={(e) => set('ip_address', e.target.value)}
            placeholder="e.g. 192.168.1.100"
            autoFocus
          />
        </div>

        <div className="field form-grid--full">
          <label className="field__label">Reason</label>
          <textarea
            className="textarea"
            maxLength={500}
            value={form.reason}
            onChange={(e) => set('reason', e.target.value)}
            placeholder="Optional — e.g. repeated SSH brute-force attempts"
            style={{ fontFamily: 'var(--font-sans)', minHeight: 56 }}
          />
        </div>
      </div>

      {error && <div className="field__error" style={{ marginTop: 12 }}>{error}</div>}

      <div className="form-actions">
        <button type="button" className="btn btn--ghost" onClick={onCancel} disabled={saving}>Cancel</button>
        <button type="submit" className="btn btn--primary" disabled={saving}>
          {saving ? 'Blocking…' : 'Block IP'}
        </button>
      </div>
    </form>
  );
}

function SkeletonTable() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="skeleton" style={{ height: 18, width: `${90 - i * 5}%` }} />
      ))}
    </div>
  );
}

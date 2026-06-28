import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Panel from '../components/Panel';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';
import { alertsApi } from '../api/alerts';
import { formatTimestamp } from '../api/format';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const STATUSES = ['new', 'acknowledged', 'resolved', 'false_positive'];

export default function Alerts() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState({ severity: '', status: '', source_ip: '' });
  const [searchInput, setSearchInput] = useState('');
  const [page, setPage] = useState(1);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await alertsApi.list({
        page,
        page_size: 25,
        severity: filters.severity || undefined,
        status: filters.status || undefined,
        source_ip: filters.source_ip || undefined,
      });
      setResult(data);
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [page, filters]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const t = setTimeout(() => {
      setPage(1);
      setFilters((f) => ({ ...f, source_ip: searchInput.trim() }));
    }, 350);
    return () => clearTimeout(t);
  }, [searchInput]);

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1;

  async function handleStatusChange(alertId, newStatus) {
    setBusyId(alertId);
    try {
      await alertsApi.updateStatus(alertId, newStatus);
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(alertId) {
    if (!window.confirm('Delete this alert? This cannot be undone.')) return;
    setBusyId(alertId);
    try {
      await alertsApi.remove(alertId);
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-header__title">Alerts</h1>
          <p className="page-header__subtitle">
            {result ? `${result.total.toLocaleString()} alert${result.total === 1 ? '' : 's'} matching current filters` : 'Loading alerts…'}
          </p>
        </div>
      </div>

      <div className="filter-bar">
        <select
          className="select"
          value={filters.severity}
          onChange={(e) => { setPage(1); setFilters((f) => ({ ...f, severity: e.target.value })); }}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        <select
          className="select"
          value={filters.status}
          onChange={(e) => { setPage(1); setFilters((f) => ({ ...f, status: e.target.value })); }}
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s.replace('_', ' ')}</option>
          ))}
        </select>

        <input
          className="input"
          placeholder="Filter by source IP…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          style={{ minWidth: 200 }}
        />

        {(filters.severity || filters.status || filters.source_ip) && (
          <button
            className="btn btn--ghost btn--sm"
            onClick={() => { setFilters({ severity: '', status: '', source_ip: '' }); setSearchInput(''); setPage(1); }}
          >
            Clear filters
          </button>
        )}
      </div>

      {error && (
        <div className="field__error" style={{ marginBottom: 12 }}>{error.message}</div>
      )}

      <Panel>
        {loading && !result ? (
          <SkeletonTable />
        ) : !result || result.alerts.length === 0 ? (
          <EmptyState
            title="No alerts found"
            body="No alerts match the current filters. Try widening your search, or wait for the detection engine to flag traffic."
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Signature</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Status</th>
                    <th>Time</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {result.alerts.map((a) => (
                    <tr key={a.id}>
                      <td onClick={() => navigate(`/alerts/${a.id}`)} className="is-clickable"><SeverityBadge severity={a.severity} /></td>
                      <td onClick={() => navigate(`/alerts/${a.id}`)} className="is-clickable">{a.signature_name || `#${a.signature_id}`}</td>
                      <td onClick={() => navigate(`/alerts/${a.id}`)} className="is-clickable mono">{a.source_ip}{a.source_port ? `:${a.source_port}` : ''}</td>
                      <td onClick={() => navigate(`/alerts/${a.id}`)} className="is-clickable mono">{a.dest_ip}{a.dest_port ? `:${a.dest_port}` : ''}</td>
                      <td onClick={() => navigate(`/alerts/${a.id}`)} className="is-clickable mono">{a.protocol?.toUpperCase()}</td>
                      <td>
                        <select
                          className="select"
                          style={{ padding: '3px 6px', fontSize: 11.5, width: 'auto' }}
                          value={a.status}
                          disabled={busyId === a.id}
                          onChange={(e) => handleStatusChange(a.id, e.target.value)}
                        >
                          {STATUSES.map((s) => (
                            <option key={s} value={s}>{s.replace('_', ' ')}</option>
                          ))}
                        </select>
                      </td>
                      <td className="cell-muted">{formatTimestamp(a.timestamp)}</td>
                      <td>
                        <button
                          className="btn btn--ghost btn--sm"
                          disabled={busyId === a.id}
                          onClick={() => handleDelete(a.id)}
                          aria-label="Delete alert"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pagination">
              <span>Page {result.page} of {totalPages}</span>
              <div className="pagination__controls">
                <button className="btn btn--ghost btn--sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
                <button className="btn btn--ghost btn--sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
              </div>
            </div>
          </>
        )}
      </Panel>
    </>
  );
}

function SkeletonTable() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="skeleton" style={{ height: 18, width: `${92 - i * 4}%` }} />
      ))}
    </div>
  );
}

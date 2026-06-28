import { useCallback, useEffect, useState } from 'react';
import Panel from '../components/Panel';
import SeverityBadge from '../components/SeverityBadge';
import EmptyState from '../components/EmptyState';
import Modal from '../components/Modal';
import SignatureForm from '../components/SignatureForm';
import { signaturesApi } from '../api/signatures';

export default function Signatures() {
  const [filters, setFilters] = useState({ enabled: '', severity: '', category: '', search: '' });
  const [searchInput, setSearchInput] = useState('');
  const [page, setPage] = useState(1);
  const [result, setResult] = useState(null);
  const [categories, setCategories] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [editing, setEditing] = useState(null); // null = closed, {} = create, {...} = edit
  const [deleteTarget, setDeleteTarget] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await signaturesApi.list({
        page,
        page_size: 25,
        enabled: filters.enabled === '' ? undefined : filters.enabled === 'true',
        severity: filters.severity || undefined,
        category: filters.category || undefined,
        search: filters.search || undefined,
      });
      setResult(data);
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    signaturesApi.categories().then((d) => setCategories(d.categories || [])).catch(() => {});
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      setPage(1);
      setFilters((f) => ({ ...f, search: searchInput.trim() }));
    }, 350);
    return () => clearTimeout(t);
  }, [searchInput]);

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1;

  async function handleToggle(sig) {
    setBusyId(sig.id);
    try {
      await signaturesApi.toggle(sig.id);
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(sig) {
    setBusyId(sig.id);
    try {
      await signaturesApi.remove(sig.id);
      setDeleteTarget(null);
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setBusyId(null);
    }
  }

  async function handleFormSubmit(data) {
    if (editing?.id) {
      await signaturesApi.update(editing.id, data);
    } else {
      await signaturesApi.create(data);
    }
    setEditing(null);
    await load();
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-header__title">Signatures</h1>
          <p className="page-header__subtitle">
            {result ? `${result.total.toLocaleString()} signature${result.total === 1 ? '' : 's'} in the ruleset` : 'Loading signatures…'}
          </p>
        </div>
        <div className="page-header__actions">
          <button className="btn btn--primary" onClick={() => setEditing({})}>+ New signature</button>
        </div>
      </div>

      <div className="filter-bar">
        <select className="select" value={filters.enabled} onChange={(e) => { setPage(1); setFilters((f) => ({ ...f, enabled: e.target.value })); }}>
          <option value="">All states</option>
          <option value="true">Active only</option>
          <option value="false">Disabled only</option>
        </select>

        <select className="select" value={filters.severity} onChange={(e) => { setPage(1); setFilters((f) => ({ ...f, severity: e.target.value })); }}>
          <option value="">All severities</option>
          {['low', 'medium', 'high', 'critical'].map((s) => (
            <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        {categories.length > 0 && (
          <select className="select" value={filters.category} onChange={(e) => { setPage(1); setFilters((f) => ({ ...f, category: e.target.value })); }}>
            <option value="">All categories</option>
            {categories.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        )}

        <input
          className="input"
          placeholder="Search name or description…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          style={{ minWidth: 220 }}
        />
      </div>

      {error && <div className="field__error" style={{ marginBottom: 12 }}>{error.message}</div>}

      <Panel>
        {loading && !result ? (
          <SkeletonTable />
        ) : !result || result.signatures.length === 0 ? (
          <EmptyState
            title="No signatures found"
            body="Adjust your filters, or create a new signature to start detecting this kind of traffic."
            action={<button className="btn btn--primary btn--sm" onClick={() => setEditing({})}>+ New signature</button>}
          />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Active</th>
                    <th>Name</th>
                    <th>Severity</th>
                    <th>Protocol</th>
                    <th>Category</th>
                    <th>Match</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {result.signatures.map((sig) => (
                    <tr key={sig.id}>
                      <td>
                        <label style={{ display: 'inline-flex', alignItems: 'center', cursor: 'pointer' }}>
                          <input
                            type="checkbox"
                            checked={sig.enabled}
                            disabled={busyId === sig.id}
                            onChange={() => handleToggle(sig)}
                            style={{ width: 16, height: 16, cursor: 'pointer' }}
                          />
                        </label>
                      </td>
                      <td className="is-clickable" onClick={() => setEditing(sig)}>
                        <div style={{ fontWeight: 600 }}>{sig.name}</div>
                        {sig.description && (
                          <div className="cell-muted col-wrap" style={{ fontSize: 11.5, marginTop: 2 }}>{sig.description}</div>
                        )}
                      </td>
                      <td><SeverityBadge severity={sig.severity} /></td>
                      <td className="mono">{sig.protocol?.toUpperCase()}</td>
                      <td className="cell-muted">{sig.category || '—'}</td>
                      <td className="mono cell-muted" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {sig.dest_port ? `:${sig.dest_port} ` : ''}{sig.pattern ? `/${sig.pattern}/` : ''}
                        {!sig.dest_port && !sig.pattern ? 'header only' : ''}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button className="btn btn--ghost btn--sm" onClick={() => setEditing(sig)}>Edit</button>
                          <button className="btn btn--ghost btn--sm" onClick={() => setDeleteTarget(sig)}>Delete</button>
                        </div>
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

      {editing !== null && (
        <Modal title={editing.id ? `Edit ${editing.name}` : 'New signature'} onClose={() => setEditing(null)}>
          <SignatureForm initial={editing.id ? editing : null} onSubmit={handleFormSubmit} onCancel={() => setEditing(null)} />
        </Modal>
      )}

      {deleteTarget && (
        <Modal title="Delete signature" onClose={() => setDeleteTarget(null)}>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.6 }}>
            Delete <strong style={{ color: 'var(--text-primary)' }}>{deleteTarget.name}</strong>? This also deletes
            every alert that was generated by this signature. This cannot be undone.
          </p>
          <div className="form-actions">
            <button className="btn btn--ghost" onClick={() => setDeleteTarget(null)}>Cancel</button>
            <button className="btn btn--danger" disabled={busyId === deleteTarget.id} onClick={() => handleDelete(deleteTarget)}>
              {busyId === deleteTarget.id ? 'Deleting…' : 'Delete signature'}
            </button>
          </div>
        </Modal>
      )}
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

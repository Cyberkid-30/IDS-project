import { useNavigate } from 'react-router-dom';
import Panel from '../components/Panel';
import StatTile from '../components/StatTile';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';
import { usePolling } from '../hooks/usePolling';
import { alertsApi } from '../api/alerts';
import { formatDuration, formatNumber, formatRelativeTime, SEVERITY_META } from '../api/format';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

export default function Dashboard({ status }) {
  const navigate = useNavigate();
  const { data: stats, loading: statsLoading } = usePolling(() => alertsApi.stats(), 5000);
  const { data: recent } = usePolling(
    () => alertsApi.list({ page: 1, page_size: 8 }),
    5000
  );

  const sevCounts = stats
    ? {
        critical: stats.critical_alerts,
        high: stats.high_alerts,
        medium: stats.medium_alerts,
        low: stats.low_alerts,
      }
    : null;
  const maxSev = sevCounts ? Math.max(1, ...Object.values(sevCounts)) : 1;

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-header__title">Dashboard</h1>
          <p className="page-header__subtitle">
            Live overview of detection activity{status?.network_interface ? ` on ${status.network_interface}` : ''}.
          </p>
        </div>
      </div>

      <div className="stat-grid">
        <StatTile
          label="Detection state"
          value={status?.detection_running ? 'RUNNING' : 'STOPPED'}
          accent={status?.detection_running ? 'var(--signal-active)' : 'var(--text-tertiary)'}
          sub={status?.start_time ? `since ${formatRelativeTime(status.start_time)}` : 'not started'}
        />
        <StatTile
          label="Packets processed"
          value={formatNumber(status?.packets_processed)}
          sub={status ? `uptime ${formatDuration(status.uptime_seconds)}` : undefined}
        />
        <StatTile
          label="Total alerts"
          value={formatNumber(stats?.total_alerts)}
          sub={stats ? `${formatNumber(stats.alerts_today)} in the last 24h` : undefined}
        />
        <StatTile
          label="New alerts"
          value={formatNumber(stats?.new_alerts)}
          accent={stats?.new_alerts ? 'var(--sev-medium)' : undefined}
          sub="awaiting triage"
        />
        <StatTile
          label="Signatures loaded"
          value={formatNumber(status?.signatures_loaded)}
          sub="active ruleset"
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 16, marginBottom: 16 }}>
        <Panel title="Recent alerts" action={<button className="btn btn--ghost btn--sm" onClick={() => navigate('/alerts')}>View all</button>}>
          {!recent ? (
            <SkeletonRows />
          ) : recent.alerts.length === 0 ? (
            <EmptyState
              title="No alerts yet"
              body="Once the detection engine matches traffic against a signature, alerts will appear here."
            />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Signature</th>
                    <th>Source</th>
                    <th>Status</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.alerts.map((a) => (
                    <tr key={a.id} className="is-clickable" onClick={() => navigate(`/alerts/${a.id}`)}>
                      <td><SeverityBadge severity={a.severity} /></td>
                      <td>{a.signature_name || `Signature #${a.signature_id}`}</td>
                      <td className="mono">{a.source_ip}{a.source_port ? `:${a.source_port}` : ''}</td>
                      <td><StatusBadge status={a.status} /></td>
                      <td className="cell-muted">{formatRelativeTime(a.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Alerts by severity">
          {!stats ? (
            <SkeletonRows count={4} />
          ) : (
            <div className="sev-bars">
              {SEVERITY_ORDER.map((sev) => {
                const meta = SEVERITY_META[sev];
                const count = sevCounts[sev];
                return (
                  <div className="sev-bar-row" key={sev}>
                    <span className="sev-bar-row__label" style={{ color: meta.color }}>
                      {meta.label}
                    </span>
                    <div className="sev-bar-row__track">
                      <div
                        className="sev-bar-row__fill"
                        style={{ width: `${(count / maxSev) * 100}%`, background: meta.color }}
                      />
                    </div>
                    <span className="sev-bar-row__count mono">{count}</span>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Panel title="Top source IPs">
          {!stats ? (
            <SkeletonRows />
          ) : stats.top_source_ips.length === 0 ? (
            <EmptyState title="No source data" body="Top offending IPs will show up here once alerts start coming in." />
          ) : (
            <RankedList
              items={stats.top_source_ips.map((s) => ({ key: s.ip, label: s.ip, count: s.count }))}
              mono
            />
          )}
        </Panel>

        <Panel title="Most triggered signatures">
          {!stats ? (
            <SkeletonRows />
          ) : stats.top_signatures.length === 0 ? (
            <EmptyState title="No signature data" body="The signatures responsible for the most alerts will be ranked here." />
          ) : (
            <RankedList
              items={stats.top_signatures.map((s) => ({ key: s.id, label: s.name, count: s.count }))}
            />
          )}
        </Panel>
      </div>
    </>
  );
}

function RankedList({ items, mono }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="sev-bars">
      {items.map((item, idx) => (
        <div className="sev-bar-row" key={item.key} style={{ gridTemplateColumns: '24px 1fr 36px' }}>
          <span className="cell-muted mono" style={{ fontSize: 11 }}>{idx + 1}</span>
          <div>
            <div className={mono ? 'mono' : undefined} style={{ fontSize: 12.5, marginBottom: 4 }}>
              {item.label}
            </div>
            <div className="sev-bar-row__track">
              <div
                className="sev-bar-row__fill"
                style={{ width: `${(item.count / max) * 100}%`, background: 'var(--signal-active)' }}
              />
            </div>
          </div>
          <span className="sev-bar-row__count mono">{item.count}</span>
        </div>
      ))}
    </div>
  );
}

function SkeletonRows({ count = 5 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skeleton" style={{ height: 16, width: `${85 - i * 8}%` }} />
      ))}
    </div>
  );
}

export const SEVERITY_META = {
  low: { label: 'Low', color: 'var(--sev-low)', bg: 'var(--sev-low-bg)' },
  medium: { label: 'Medium', color: 'var(--sev-medium)', bg: 'var(--sev-medium-bg)' },
  high: { label: 'High', color: 'var(--sev-high)', bg: 'var(--sev-high-bg)' },
  critical: { label: 'Critical', color: 'var(--sev-critical)', bg: 'var(--sev-critical-bg)' },
};

export const STATUS_META = {
  new: { label: 'New', color: 'var(--status-new)' },
  acknowledged: { label: 'Acknowledged', color: 'var(--status-ack)' },
  resolved: { label: 'Resolved', color: 'var(--status-resolved)' },
  false_positive: { label: 'False positive', color: 'var(--status-false)' },
};

export function formatTimestamp(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatRelativeTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diffMs = Date.now() - d.getTime();
  const sec = Math.floor(diffMs / 1000);
  if (sec < 5) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const days = Math.floor(hr / 24);
  return `${days}d ago`;
}

export function formatDuration(seconds) {
  if (seconds == null) return '—';
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86400);
  const hrs = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  if (days > 0) return `${days}d ${hrs}h ${mins}m`;
  if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

export function formatNumber(n) {
  if (n == null) return '—';
  return n.toLocaleString();
}

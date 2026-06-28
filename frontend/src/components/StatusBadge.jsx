import { STATUS_META } from '../api/format';

export default function StatusBadge({ status }) {
  const meta = STATUS_META[status] || { label: status, color: 'var(--text-tertiary)' };
  return (
    <span className="status-pill">
      <span className="status-pill__dot" style={{ background: meta.color }} />
      <span style={{ color: meta.color }}>{meta.label}</span>
    </span>
  );
}

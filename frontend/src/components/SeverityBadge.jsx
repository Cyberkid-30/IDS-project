import { SEVERITY_META } from '../api/format';

export default function SeverityBadge({ severity }) {
  const meta = SEVERITY_META[severity] || { label: severity, color: 'var(--text-tertiary)', bg: 'transparent' };
  return (
    <span
      className="badge mono"
      style={{ color: meta.color, background: meta.bg, borderColor: meta.color }}
    >
      {meta.label}
    </span>
  );
}

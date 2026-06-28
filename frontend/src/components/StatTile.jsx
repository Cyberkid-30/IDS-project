export default function StatTile({ label, value, accent, sub, icon }) {
  return (
    <div className="stat-tile">
      <div className="stat-tile__top">
        <span className="stat-tile__label">{label}</span>
        {icon && <span className="stat-tile__icon">{icon}</span>}
      </div>
      <div className="stat-tile__value mono" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {sub && <div className="stat-tile__sub">{sub}</div>}
    </div>
  );
}

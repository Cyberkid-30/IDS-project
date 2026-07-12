import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './NavRail.css';

const ICONS = {
  dashboard: (
    <svg viewBox="0 0 20 20" fill="none">
      <rect x="2.5" y="2.5" width="6" height="8" rx="1" stroke="currentColor" strokeWidth="1.4" />
      <rect x="11.5" y="2.5" width="6" height="5" rx="1" stroke="currentColor" strokeWidth="1.4" />
      <rect x="11.5" y="10.5" width="6" height="7" rx="1" stroke="currentColor" strokeWidth="1.4" />
      <rect x="2.5" y="13.5" width="6" height="4" rx="1" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  ),
  alerts: (
    <svg viewBox="0 0 20 20" fill="none">
      <path d="M10 2.5l7.5 13.5h-15L10 2.5z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <line x1="10" y1="8" x2="10" y2="11.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="10" cy="14" r="0.9" fill="currentColor" />
    </svg>
  ),
  signatures: (
    <svg viewBox="0 0 20 20" fill="none">
      <path d="M3 4h14M3 8h14M3 12h9M3 16h6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  ),
  system: (
    <svg viewBox="0 0 20 20" fill="none">
      <circle cx="10" cy="10" r="2.6" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M10 3v2.2M10 14.8V17M17 10h-2.2M5.2 10H3M14.9 5.1l-1.5 1.5M6.6 13.4l-1.5 1.5M14.9 14.9l-1.5-1.5M6.6 6.6L5.1 5.1"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  ),
};

const ITEMS = [
  { to: '/', label: 'Dashboard', icon: 'dashboard', end: true },
  { to: '/alerts', label: 'Alerts', icon: 'alerts' },
  { to: '/signatures', label: 'Signatures', icon: 'signatures' },
  { to: '/system', label: 'System', icon: 'system' },
];

export default function NavRail() {
  const { user, logout } = useAuth();

  return (
    <nav className="nav-rail">
      <div className="nav-rail__brand">
        <span className="nav-rail__mark" aria-hidden="true">◈</span>
        <div>
          <div className="nav-rail__title">SENTRYWATCH</div>
          <div className="nav-rail__subtitle mono">IDS console</div>
        </div>
      </div>

      <div className="nav-rail__items">
        {ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => `nav-rail__item ${isActive ? 'is-active' : ''}`}
          >
            <span className="nav-rail__icon">{ICONS[item.icon]}</span>
            <span>{item.label}</span>
          </NavLink>
        ))}
      </div>

      <div className="nav-rail__user">
        <span className="nav-rail__username mono" title={user?.username}>
          {user?.username ?? '—'}
        </span>
        <button className="nav-rail__logout" onClick={logout} title="Log out">
          Log out
        </button>
      </div>
      <div className="nav-rail__footer mono">v1.0.0</div>
    </nav>
  );
}

import { useNavigate } from 'react-router-dom';

export default function ConnectionBanner({ message }) {
  const navigate = useNavigate();
  return (
    <div className="connection-banner">
      <span className="connection-banner__dot" />
      <span>{message}</span>
      <button className="connection-banner__action" onClick={() => navigate('/system')}>
        Check connection
      </button>
    </div>
  );
}

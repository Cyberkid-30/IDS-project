import './PulseStrip.css';

/**
 * The watchdog heartbeat. A thin horizontal strip that sweeps like a
 * radar/EKG trace while detection is running, and flatlines when it's not.
 * This is the one persistent answer to "is the IDS actually watching right now."
 */
export default function PulseStrip({ running, packetsPerSecond = 0 }) {
  return (
    <div className={`pulse-strip ${running ? 'is-active' : 'is-idle'}`} role="status"
      aria-label={running ? 'Detection engine running' : 'Detection engine stopped'}>
      <svg
        className="pulse-strip__trace"
        viewBox="0 0 1200 36"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        {running ? (
          <path
            className="pulse-strip__path pulse-strip__path--active"
            d="M0,18 L120,18 L132,4 L144,32 L156,18 L900,18 L912,4 L924,32 L936,18 L1200,18"
            fill="none"
          />
        ) : (
          <path
            className="pulse-strip__path pulse-strip__path--idle"
            d="M0,18 L1200,18"
            fill="none"
          />
        )}
      </svg>
      <div className="pulse-strip__label">
        <span className={`pulse-strip__dot ${running ? 'is-active' : 'is-idle'}`} />
        <span className="mono pulse-strip__text">
          {running ? 'DETECTION ACTIVE' : 'DETECTION STOPPED'}
        </span>
        {running && packetsPerSecond != null && (
          <span className="mono pulse-strip__rate">{packetsPerSecond.toFixed(1)} pkt/s</span>
        )}
      </div>
    </div>
  );
}

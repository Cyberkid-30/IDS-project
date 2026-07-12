# SentryWatch — IDS Console

A React dashboard for the [Network Intrusion Detection System backend](../backend). Gives you a live view of detection status, alerts, and signatures without touching the API directly.

## Features

- **Dashboard** — detection state, packet/alert counters, severity breakdown, recent alerts, top source IPs, most-triggered signatures
- **Alerts** — paginated, filterable (severity, status, source IP) alert list; inline status updates; delete; full alert detail view with payload snippet
- **Signatures** — full CRUD on detection signatures, including enable/disable toggles, category and severity filters, and regex pattern validation feedback from the API
- **System** — start/stop the detection engine, reload signatures, view network interfaces and configuration, run alert cleanup, and point the dashboard at a different backend URL
- A persistent **pulse strip** showing at a glance whether the detection engine is currently running

The dashboard polls the backend (`/api/v1/system/status` and friends) every few seconds, so it stays in sync without a manual refresh, and pauses polling while the tab is hidden.

## Requirements

- Node.js 18+
- The IDS backend running and reachable (see `../backend/README.md`)

## Quick start

```bash
cd frontend
npm install
npm run dev
```

This starts the Vite dev server, typically at `http://localhost:5173`.

By default, the dashboard talks to the backend at `http://localhost:8000`. If your backend is running elsewhere, open the **System** page and update the **Backend connection** API base URL — it's saved in your browser and the page reloads automatically.

## Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the dev server with hot reload |
| `npm run build` | Production build to `dist/` |
| `npm run preview` | Preview the production build locally |
| `npm run lint` | Run Oxlint |

## Project structure

```
src/
├── api/             # Thin fetch wrappers per backend resource (alerts, signatures, system)
│   ├── client.js     # Shared request helper, error handling, configurable base URL
│   └── format.js     # Display formatting (timestamps, durations, severity/status labels)
├── components/       # Reusable UI primitives (Panel, Modal, badges, nav rail, pulse strip)
├── hooks/
│   └── usePolling.js # Polls a fetcher on an interval, pausing when the tab is hidden
├── pages/            # One component per route: Dashboard, Alerts, AlertDetail, Signatures, System
├── styles/           # Design tokens (CSS variables) and shared component styles
├── App.jsx           # Route definitions and shared layout (nav rail, pulse strip, connection banner)
└── main.jsx           # Entry point
```

## Configuration

There's no build-time environment variable for the backend URL — it's set at runtime from the **System** page and stored in `localStorage` under `ids_api_base_url`. This makes it easy to point the same build at different backends (e.g. local vs. a lab VM) without rebuilding.

## Notes

- This app expects the backend's `/api/v1` routes as documented in the backend README. If you change the API prefix or response shapes on the backend, update `src/api/*.js` and `src/api/format.js` to match.
- No authentication is implemented on either side — this is intended for a local lab / trusted network setup, not public exposure.

# Phase 16 — Dashboard & Visualization

## Objective

Provide a professional React/Vite SOC dashboard on top of the Phase 15 API and WebSocket contracts.

## Design rules

- The frontend is a presentation/client layer.
- Detection, risk, correlation, alert lifecycle, incident workflow, IOC matching, and MITRE logic remain backend responsibilities.
- API calls are centralized in `src/services/api.ts`.
- WebSocket reconnect behavior is centralized in `src/services/websocket.ts`.
- Shared UI state is held in the Zustand dashboard store.
- Pages do not create duplicate backend business logic.

## Implemented views

- SOC Overview
- Security Events
- Alerts
- Incidents
- Threat Intelligence
- Detection Operations boundary
- MITRE Coverage
- Assets boundary
- Risk boundary
- System Health

## Configuration

Copy `frontend/.env.example` to `.env` and set the Phase 15 API/WebSocket base URLs.

## Validation

From `frontend/`:

```bash
npm install
npm run typecheck
npm test
npm run build
```

The project intentionally does not add authentication/RBAC; those belong to Phase 17.

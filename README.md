# IGU Sentinel — Frontend (batch mode)

Plain HTML/JS dashboard, no build step. Talks to the existing `api/` FastAPI
app via `POST /detect`. There is no WebSocket endpoint yet — this is
Phase-2's `api/` task pending item — so this UI polls/triggers batches
instead of streaming.

## Run it

Just open `index.html` in a browser, or serve the folder:

```bash
cd frontend
python -m http.server 5500
```

Then set the "API Base URL" field to wherever the FastAPI app is running
(default assumed: `http://localhost:8000`).

## Required backend change: CORS

The current `api/` app has no `CORSMiddleware`, so browser requests from
this frontend (a different origin/port) will be blocked. Add to the FastAPI
app:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before demo/prod
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## How it works

- Load flows either via a fixture JSONL/JSON file or by pasting a
  FlowRecord JSON array into the textarea.
- "Run Detection" POSTs the flows to `/detect` and renders the returned
  `Alert` list.
- "Auto re-run" re-submits the same loaded flows on an interval — this is
  a stand-in for live streaming, not real new traffic.
- Chain status pill shows "n/a" because the current `Alert` schema
  (`schemas.py`) has no hash-chain fields — those live in the pending
  `alert/` module. Once that's wired into the API response, extend
  `normalizeAlert()` in `app.js` to read `prev_hash`/`hash`/`verified`
  and flip the pill to ok/broken.

## Swapping in the WebSocket later

All alert-fetching logic is isolated in `dataSource.js` behind a small
interface (`onAlerts`, `onError`, `onModeChange`, `runDetection`/`connect`).
When the backend adds a WS endpoint:

1. Confirm the URL path and message shape (single `Alert` per message vs.
   batched array).
2. In `dataSource.js`, finish `WebSocketAlertSource` (already stubbed) to
   match that shape.
3. In `app.js`, change `createAlertSource()` to return
   `new WebSocketAlertSource(apiBase)` and call `.connect()` instead of
   `.startPolling()`.

No other file needs to change — `app.js` only talks to the `source`
interface, not to fetch/WebSocket directly.

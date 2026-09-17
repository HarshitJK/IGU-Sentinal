# IGU Sentinel — Changes Applied

Security and correctness audit, 2026-09-17. Everything here is **implemented,
tested and present in the working tree**. Companion documents:

- [REMAINING_FIXES.md](REMAINING_FIXES.md) — what is *not* fixed (38 items).
- [DATASET_EVALUATION.md](DATASET_EVALUATION.md) — model evaluation findings.

**Test status:** 126 passed, 12 skipped (Docker not installed on this machine).
Before the audit: 103 passed, 12 **failed**.

**Git status:** no commits were made. All changes are uncommitted in the working
tree on `main`, as requested.

---

## Contents

- [The three that mattered](#the-three-that-mattered)
- [Security fixes](#security-fixes)
- [Correctness fixes](#correctness-fixes)
- [Performance](#performance)
- [Infrastructure](#infrastructure)
- [New files](#new-files)
- [Tests added](#tests-added)
- [File-by-file summary](#file-by-file-summary)
- [Configuration reference](#configuration-reference)
- [Verifying it yourself](#verifying-it-yourself)

---

## The three that mattered

### 1. The tamper-evident audit log was forgeable

**File:** `igu_sentinel/alert/__init__.py` (rewritten)

Each entry's hash covered **only its own content**. `prev_hash` was stored
beside it but was not covered by any hash. That is not a chain — it is a list of
independently-hashed records with a decorative pointer.

Demonstrated before fixing:

```
original chain valid: True
edit entry 1, recompute its content hash, patch entry 2's prev_hash to match
after forging entry 1, chain valid: True        <-- should be False
```

An attacker could rewrite any alert — change its `threat_class`, drop its
`confidence_score`, replace its evidence — and `verify_alert_chain()` still
returned `True`.

**Fixed.** The hash now commits to `(seq, prev_hash, content)` together:

```python
def _preimage(seq, prev_hash, content):
    return json.dumps(
        {"seq": seq, "prev_hash": prev_hash, **{k: content[k] for k in _CONTENT_FIELDS}},
        sort_keys=True, separators=(",", ":"), default=str,
    )
```

Because `prev_hash` is inside the preimage, editing entry *k* changes `hash_k`,
which invalidates `hash_{k+1}`, and so on to the head. Also added:

- **Sequence numbers** — catches deletion and insertion, which pointer-only
  chaining misses.
- **`get_chain_head()`** — pin externally to detect a wholesale rewrite.
- **Optional HMAC-SHA256** via `IGU_ALERT_HMAC_KEY` — plain SHA-256 only stops
  an attacker who cannot recompute the chain; with the key they cannot forge it
  at all.
- **`hmac.compare_digest`** for hash comparison.
- **Thread safety** — the chain is appended from the capture thread and request
  handlers concurrently; it was previously unlocked.
- **Bounded memory** — `_alert_log` was an unbounded list that grew forever
  under sustained capture. Now a `deque(maxlen=...)`, configurable via
  `IGU_ALERT_LOG_MAX`. Verification handles a run that starts after truncation.

**Regression test:** `test_alert_verify_detects_chain_rewrite` performs the exact
forgery above and asserts it is now caught. Plus deletion detection and
chain-head advancement.

> Still open: the chain is in-memory and resets on restart — see R15.

---

### 2. The diode enforced nothing

**File:** `docker-compose.yml`

This container is the project's security boundary. It ran:

```yaml
image: busybox:latest
command:
  - -c
  - |
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -P FORWARD DROP
    iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
    iptables -A FORWARD -i eth1 -o eth0 -j DROP
    echo 'Diode online'
```

Three independent failures:

1. **busybox ships no `iptables` applet.** Every rule failed with
   `iptables: not found`.
2. **No `set -e`.** The script continued past every failure and printed
   `Diode online` regardless. The diode reported success while enforcing nothing.
3. **`/proc/sys` is read-only** in an unprivileged container, so the
   `ip_forward` write failed too.

Separately, `eth0`/`eth1` were assumed. **Docker does not guarantee which
network becomes which interface** — the one-way rules could be installed
backwards, silently inverting the diode's direction.

**Fixed:**

- `alpine:3.20` with `iptables` installed — an image that can actually enforce.
- `-eu` so any failed step kills the container instead of leaving a permissive
  box that looks healthy.
- `ip_forward` set via the compose `sysctls:` key, not a doomed `echo`.
- **Interfaces resolved from subnets at runtime**, not assumed:
  ```sh
  PROD_IF=$(ip -o -4 addr show | awk '$4 ~ /^172\.31\.10\./ {print $2; exit}')
  ENCL_IF=$(ip -o -4 addr show | awk '$4 ~ /^172\.31\.20\./ {print $2; exit}')
  ```
  with the networks given explicit non-overlapping subnets.
- **Rules read back before reporting ready** — `iptables -C` for each rule plus a
  policy check. A diode that cannot prove its own enforcement does not come up.

> **Not verified by execution.** Docker is not installed on this machine. See
> [Unverified work](REMAINING_FIXES.md#unverified-work) for the exact commands
> to run on a Linux host before relying on this.

---

### 3. The pipeline ran at 112 flows/sec

CLAUDE.md makes throughput a graded requirement. Profiling each layer found it
immediately:

| layer | per-flow | batched | ratio |
|---|---:|---:|---:|
| rules | 432,875/s | — | — |
| stats | 364,945/s | — | — |
| **isoforest** | **146/s** (6.8 ms/flow) | **14,160/s** | **97×** |
| xgb | 1,076/s | 397,022/s | 369× |

Both ML layers were invoked **once per flow**. Their fixed per-call overhead —
input validation, tree-ensemble dispatch, and with `n_jobs=-1` a thread hand-off
— dwarfs the work of scoring one 16-feature row.

Worse, the `ThreadPoolExecutor`-per-call "concurrency" was actively **slower**
than sequential (112 vs 136 flows/sec): the work is GIL-bound, so the fan-out
bought nothing and the pool setup was pure overhead, paid on every call.

**Fixed.** Added `score_isoforest_batch()` and `predict_xgb_batch()`; the
pipeline now scores one capture window per call. The per-flow functions remain as
the CLAUDE.md contract and delegate to the batch versions, so there is exactly
one implementation of each.

```
112 flows/sec  →  11,746 flows/sec        (~105×)
p95 latency 11.2 ms per 128-flow batch
1,409 flows per 120 ms window · 90.7% of the window budget free
```

The 120 ms capture window is unchanged — it remains fixed and non-adaptive, as
locked in CLAUDE.md.

---

## Security fixes

### The API was completely unauthenticated

`/detect`, `/capture/start`, `/capture/stop`, `/capture/status` and `/ws/alerts`
had no access control. Anyone who could reach the port could **start a packet
capture on any interface of the host** and read the live threat-alert feed.

Added (`igu_sentinel/api/__init__.py`):

- **Bearer-token auth** via `IGU_API_TOKEN`, using `hmac.compare_digest` so a
  wrong token cannot be recovered by timing. Off by default so the local demo
  still runs with no setup; a loud startup warning fires when unset.
- **CORS allowlist** via `IGU_ALLOWED_ORIGINS`, deny-by-default.
- **WebSocket Origin check.** This one matters on its own: **WebSockets are not
  covered by the browser same-origin policy**, so any web page the operator
  visited could open `ws://localhost:8000/ws/alerts` and read the alert stream.
  CORS does not stop this; the handshake check does.
- `/health` deliberately stays open so container healthchecks work.

> **Caveat:** neither dashboard sends a token, so enabling `IGU_API_TOKEN`
> currently breaks both UIs — see R16.

### `/detect` returned HTTP 500 on malformed input

`FlowRecord(**f)` raised `ValidationError` straight out of the handler.
Malformed input is a client error, and 500 also leaks a stack trace.

Now returns **422** naming the offending index:

```python
except (ValidationError, TypeError) as exc:
    raise HTTPException(status_code=422, detail={
        "error": "invalid FlowRecord", "index": idx, "reason": str(exc)})
```

### `/detect` accepted unbounded batches

One request could pin arbitrary memory. Now **413** above
`MAX_FLOWS_PER_REQUEST` (default 10,000, configurable).

### One slow WebSocket client stalled everything

`broadcast_alert()` awaited each `send_json` serially with no timeout. A wedged
client blocked delivery to every other client — and on the live-capture path,
blocked the capture thread that was waiting on the coroutine, so dashboard
latency backpressured packet capture itself.

Now concurrent with a per-connection timeout; a client that times out is treated
as dead and dropped. The capture worker no longer blocks on delivery at all
(fire-and-forget with an error callback, replacing `fut.result(timeout=5)`).

### Model/scaler torn reads

`isoforest.py` held `_model`, `_scaler`, `_platt_b`, `_DF_SCALE` as four separate
module globals. They are only meaningful **together** — a scaler fitted for one
forest produces garbage for another. A retrain could swap the model in between a
scorer reading `_scaler` and reading `_model`, silently corrupting every score
until the next swap.

Both detectors now hold one immutable tuple rebound under a lock, which is what
makes CLAUDE.md's "swaps in a retrained model atomically" claim actually true.
Scorers take one consistent snapshot.

### Pickle deserialization hardening

`joblib.load()` unpickles, which executes arbitrary code. Added path containment
(nothing outside `models/` loads), bundle-shape validation, and a feature-dimension
check so a stale artifact fails loudly at load instead of producing meaningless
scores.

> **Not closed** — anyone who can write to `models/` still gets code execution.
> See R14 for the signed-manifest fix.

### Corrupt label maps crashed the scoring path

`predict_xgb` synthesised `f"class_{i}"` for any unmapped index. That propagated
through fusion into `Alert(threat_class=...)`, which only accepts the six
mandated classes — so a bad artifact raised `ValidationError` **per flow**,
taking down scoring rather than degrading.

Now the label map is validated against `THREAT_CLASSES` at load time (refusing
the artifact once, loudly), unmapped indices are dropped rather than invented,
and fusion independently ignores out-of-schema votes while keeping that layer's
evidence.

---

## Correctness fixes

### `is_malicious_ja4()` flagged every no-SNI handshake as malware

```python
if len(ja4) >= 10:
    if ja4[3] == "i":      # no domain SNI
        return True        # <-- "this is malware"
```

No SNI is ordinary — every TLS connection to a bare IP has it, which on a
monitored segment includes health checks, container-to-container traffic and
captive-portal checks. Three compounding effects:

1. False positives at a hard **+0.40** IOC weight.
2. It made `has_no_sni_ja4()` redundant, so the weaker *corroborated* branch in
   `rules.py` (`elif has_no_sni_ja4(...) and entropy > 6.5`) was **unreachable
   dead code** — the strong uncorroborated rule always won first.
3. Model features 13 and 14 became **perfectly collinear**, wasting a dimension
   and letting the classifier key on "no SNI" alone.

Now an exact IOC-list match only. The no-SNI signal remains available through
`has_no_sni_ja4()`, where it is correctly weighted alongside entropy.

### `drift/` was dead code

The module existed and was marked complete in TASKS.md. In fact:

- `trigger_bounded_retrain()` appended a log line and returned. It never
  retrained, never bounded anything, and kept no fallback model.
- `monitor_drift()` compared each window to **the previous window**. An attacker
  can walk the baseline anywhere by taking small steps — every individual step
  looks drift-free, so nothing ever fires. Gradual poisoning was invisible by
  construction.
- PSI used `(count + 0.5) / (len(data) + len(bin_edges))`. `len(bin_edges)` is
  `bins + 1`, not a count of anything, so PSI was off the scale the 0.2
  literature threshold refers to.
- Bin edges came from the **combined** range of both samples, letting the current
  sample move the bins it is measured against — damping exactly the large shifts
  it should catch.
- **Nothing in the pipeline called any of it.**

Rewritten:

- Drift measured against the **frozen original** baseline, captured once and
  never overwritten (`set_baseline_distribution` is idempotent).
- PSI with baseline-anchored bins, out-of-range mass clamped into edge bins, and
  correct Laplace smoothing (`0.5 * bins`).
- KS statistic added, with correct tie handling — the naive merge reports a
  spurious `1/n` gap for two identical samples.
- **Real bounded retrain**: snapshot the original model permanently, retrain on
  candidates, measure the boundary shift, and **roll back** if it exceeds
  `MAX_BOUNDARY_SHIFT_PSI`.
- **Anti-poisoning**: `submit_confirmed_benign()` is the only way flows enter the
  retrain pool, and the pipeline feeds it only flows the **fused cross-layer
  verdict** cleared — never flows isoforest merely scored low.
- `rollback_to_baseline()` for permanent fallback.
- **Wired into the scoring path**, guarded so a drift bookkeeping error can never
  drop a detection.

> Still open: nothing calls `trigger_bounded_retrain()` automatically — R13.

### Missing dependency

`joblib` is imported directly by `isoforest.py` but was **absent from
`requirements.txt`** — it worked only because scikit-learn happens to pull it in.
Model persistence depended on another package's dependency graph not changing.

### Unpinned dependencies

Every constraint was a bare `>=`, so `pip install -r` resolved to whatever was
newest that day. Two people, or a rebuild a month apart, got different dependency
sets from the same commit — a correctness problem for a system whose evaluation
numbers must be reproducible. All constraints now carry upper bounds.

### Hot-path imports

`detect_rules()` ran `import math` and a `from ... import` **inside the function**
— once per flow, re-entering the import machinery on the hot path. Hoisted.

### Tests polluted the production model directory

Discovered late: the new drift tests call `trigger_bounded_retrain()` →
`train_isoforest()`, which persists a new versioned artifact. `conftest.py`
redirected `_MODELS_DIR` only for `test_isoforest` and `test_xgb`, so drift tests
wrote 18 models into the real `models/` directory — and because the loader takes
the **highest version**, the next service start would have served a model trained
on test fixtures, including a deliberately poisoned pool.

`test_drift` added to the isolation set; the 18 stray artifacts removed. Verified
a full test run now leaves `models/` unchanged, still serving `isoforest_v18.pkl`.

> This is the same failure mode that produced the far more serious
> [served-model finding](DATASET_EVALUATION.md#1-the-served-model-is-not-the-model-that-was-evaluated).

---

## Performance

Beyond the 105× batching win:

- **Removed per-call `ThreadPoolExecutor` and `asyncio.run()`.** The sync
  pipeline entry point created a fresh pool (or a whole event loop) on every
  call and dispatched four tasks per flow.
- **Batch scoring moved to `asyncio.to_thread`** so the event loop stays
  responsive to WebSocket clients while a window is scored.
- **Fixed a degenerate metric I first wrote myself.** My initial
  `window_headroom` derived headroom from throughput, which reduces algebraically
  to `1 - 120/120 = 0` for *any* throughput — it reported a saturated pipeline no
  matter how fast it was. Now computed from measured p95 batch latency, with a
  test (`test_benchmark_window_headroom_is_not_degenerate`) pinning it.

---

## Infrastructure

### Dockerfile

- **Ran as root** for no reason — now a non-root `sentinel` user (uid 10001).
- **Shipped no `tshark`** — the only external process the pipeline needs. Every
  `/capture/*` call would have failed at runtime. Now installed, with
  `DEBIAN_FRONTEND=noninteractive` so the wireshark postinst prompt cannot hang
  the build.
- **Shipped no `models/`** — the service would start, then raise "model not
  available" on every scoring call.

> R20: capture as non-root still needs `setcap` on `dumpcap`.

### macvlan networks broke `compose up` everywhere

Both macvlan networks pinned `parent: wlp8s0` — one developer's wireless
interface. On any other host, network creation failed and **took the entire
stack down with it**, which is why every Docker-dependent test failed. macvlan
is also Linux-only.

Moved to an opt-in `docker-compose.macvlan.yml` overlay with the parent as a
required variable. The base stack now works anywhere.

### Docker tests failed instead of skipping

12 tests hard-failed with `RuntimeError: docker-compose: command not found`. A
missing tool is an environment gap, not a defect — red tests that say nothing
about the code train people to ignore red tests.

They also invoked the **legacy `docker-compose` v1 binary**, which Docker
removed in favour of the `docker compose` plugin — so they failed even *with*
Docker installed.

Added `compose_command()` (resolves either implementation) and `docker_available()`
(checks CLI **and** a reachable daemon), plus a collection hook that skips only
the 12 tests that genuinely drive containers. The static YAML tests still run
everywhere — they are what catches a broken compose file in CI.

### CI did not exist

Added `.github/workflows/ci.yml`: test matrix on Python 3.11/3.12 with tshark
installed, the benchmark run on every push so the throughput number is produced
rather than quoted, and a `docker` job that builds the stack and **proves the
diode blocks the return path** — the one integration test that must never
silently skip.

### Makefile

- Hardcoded `docker-compose` v1 → resolves v2 with fallback.
- Added `make venv` (the bundled `.venv` is a Linux virtualenv and cannot run on
  macOS — see R32) and `make benchmark`.

---

## New files

| File | Why |
|---|---|
| `igu_sentinel/benchmark/__init__.py` | CLAUDE.md requires a benchmark **harness module** and calls it graded. Only `tests/test_benchmark.py` existed — a test that printed a number and discarded it, with the TASKS.md box already ticked. Building it is what surfaced the 112 flows/sec bottleneck. |
| `igu_sentinel/benchmark/__main__.py` | `python -m igu_sentinel.benchmark` |
| `docker-compose.macvlan.yml` | Opt-in macvlan overlay |
| `.github/workflows/ci.yml` | CI |
| `REMAINING_FIXES.md` | 38 unfixed items |
| `DATASET_EVALUATION.md` | Model evaluation findings |
| `CHANGES_APPLIED.md` | This file |

The benchmark harness reports sustained throughput (mean over repeated passes,
so one lucky pass cannot flatter it), p50/p95/p99/max latency (percentiles, not a
mean — the tail is what a bounded-latency claim is about), and how much of the
120 ms window budget scoring consumes.

---

## Tests added

**+23 tests** (103 → 126), each pinning a specific defect.

| Test | Pins |
|---|---|
| `test_alert_verify_detects_chain_rewrite` | The exact forgery that defeated the old chain |
| `test_alert_verify_detects_entry_deletion` | Deletion via sequence gap |
| `test_alert_chain_head_advances` | Head commits to every entry |
| `test_api_detect_rejects_malformed_flow` | 422 not 500 |
| `test_api_detect_rejects_oversize_batch` | 413 |
| `test_api_capture_start_rejects_bad_interface` | Interface allowlist |
| `test_api_requires_token_when_configured` | Auth on `/detect` + `/capture/*`, `/health` open |
| `test_api_websocket_rejects_bad_token` | Alert stream not readable without the token |
| `test_api_websocket_rejects_disallowed_origin` | WS bypasses CORS |
| `test_psi_is_measured_against_the_original_baseline` | **Gradual poisoning** — walks the distribution in small steps and asserts cumulative drift is caught |
| `test_set_baseline_distribution_is_idempotent` | Baseline never overwritten |
| `test_psi_identical_distributions_is_near_zero` | PSI scale |
| `test_psi_crosses_literature_threshold_on_real_shift` | PSI vs the 0.2 threshold |
| `test_ks_statistic_bounds` | KS tie handling |
| `test_retrain_requires_fused_confirmed_benign_flows` | Anti-poisoning gate |
| `test_bounded_retrain_refuses_excessive_boundary_shift` | **Feeds attack traffic in as "benign"** and asserts the bound rejects it |
| `test_rollback_restores_original_baseline_model` | Permanent fallback |
| `test_rollback_without_snapshot_reports_failure` | Graceful failure |
| `test_benchmark_harness_reports_concrete_numbers` | Real measurement, ordered percentiles |
| `test_benchmark_window_headroom_is_not_degenerate` | The circular-metric bug |
| `test_benchmark_report_and_json_render` | Both output formats |
| `test_benchmark_loads_every_threat_class_fixture` | All seven classes |
| `test_batched_scoring_beats_per_flow_scoring` | **Regression guard on the 105× win** |

Also rewrote `test_diode_iptables_rules_configured` to assert the diode's
*properties* (default-deny, one permitted direction, runtime interface
resolution, read-back verification, non-busybox image, fail-closed) instead of
the literal `eth0`/`eth1` strings, which were the bug.

---

## File-by-file summary

| File | Change |
|---|---|
| `igu_sentinel/alert/__init__.py` | Rewritten — real hash chain, HMAC option, thread safety, bounded log |
| `igu_sentinel/api/__init__.py` | Auth, CORS, WS origin check, 422/413, batch scoring, drift wiring, non-blocking broadcast |
| `igu_sentinel/drift/__init__.py` | Rewritten — real PSI/KS, frozen baseline, bounded retrain, rollback, anti-poisoning pool |
| `igu_sentinel/detect/isoforest.py` | Batch scorer, atomic state, load hardening, drift lifecycle hooks |
| `igu_sentinel/detect/xgb.py` | Batch predictor, atomic state, label-map validation |
| `igu_sentinel/detect/features.py` | `is_malicious_ja4()` no longer flags all no-SNI traffic |
| `igu_sentinel/detect/rules.py` | Hot-path imports hoisted |
| `igu_sentinel/fusion/__init__.py` | Out-of-schema class votes ignored, evidence still kept |
| `docker-compose.yml` | Diode rewritten; subnets pinned; macvlan split out |
| `Dockerfile` | Non-root, tshark, models |
| `requirements.txt` | `joblib` added; all constraints upper-bounded |
| `Makefile` | compose v2, `venv` and `benchmark` targets |
| `tests/conftest.py` | Docker gating, drift isolation, `test_drift` model isolation |
| `scripts/red-button.sh` | compose v2 |
| `CLAUDE.md` | "Open questions" — 10 items, per the working agreement |
| `TASKS.md` | Audit notes on four falsely-ticked boxes |

---

## Configuration reference

All new settings are environment variables; every one has a safe default.

| Variable | Default | Purpose |
|---|---|---|
| `IGU_API_TOKEN` | *(unset)* | Bearer token for `/detect`, `/capture/*`, `/ws/alerts`. Unset = **no auth** (warned at startup). |
| `IGU_ALLOWED_ORIGINS` | *(unset)* | Comma-separated CORS + WebSocket Origin allowlist. Unset = same-origin only. |
| `IGU_MAX_FLOWS_PER_REQUEST` | `10000` | `/detect` batch cap (413 above). |
| `IGU_ALERT_LOG_MAX` | `100000` | In-memory alert ring-buffer size. |
| `IGU_ALERT_HMAC_KEY` | *(unset)* | Switches the chain to HMAC-SHA256. **Set this in any real deployment.** |
| `DIODE_MACVLAN_PARENT` | *(required for the overlay)* | Host interface for macvlan. |

Recommended for anything beyond localhost:

```bash
export IGU_API_TOKEN="$(openssl rand -hex 32)"
export IGU_ALERT_HMAC_KEY="$(openssl rand -hex 32)"
export IGU_ALLOWED_ORIGINS="https://your-dashboard.example"
```

---

## Verifying it yourself

```bash
rm -rf .venv && make venv          # the bundled .venv is a Linux venv (R32)
source .venv/bin/activate

pytest -q                          # expect 126 passed, 12 skipped
python -m igu_sentinel.benchmark --flows 2000 --repeats 3

# the hash-chain forgery is caught
pytest tests/test_alert.py::test_alert_verify_detects_chain_rewrite -v

# the 105x batching win has a regression guard
pytest tests/test_benchmark.py::test_batched_scoring_beats_per_flow_scoring -v

# gradual model poisoning is caught
pytest tests/test_drift.py::test_psi_is_measured_against_the_original_baseline -v

# auth actually blocks
IGU_API_TOKEN=secret pytest tests/test_api.py -k token -v
```

On a Linux host with Docker, additionally:

```bash
make diode-proof                   # must print PASS
```

---

## What this audit did not do

- **Did not verify any Docker change by execution** — Docker is not installed
  here. The diode fix is reviewed, not proven. See
  [Unverified work](REMAINING_FIXES.md#unverified-work).
- **Did not fix the traffic generator** (R1/R2) — the constant-vector problem is
  the largest remaining risk to the project's credibility, but fixing it properly
  means either real tool invocation or a generator redesign, and that is a scope
  decision for you.
- **Did not delete the broken `.venv`** — your directory, your call (R32).
- **Did not resolve the fusion design questions** (R7/R8) — recorded under
  "Open questions" in CLAUDE.md rather than decided unilaterally, per the working
  agreement.
- **Did not commit anything** — all changes are uncommitted in the working tree,
  as requested.

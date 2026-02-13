# Live Validation Runbook

This runbook separates in-repo completion from live infrastructure validation.

## Status Model

- `Code Complete`: local compile/tests/docs complete.
- `Live Validated`: live VPS validation gates passed.
- `Published`: release tagged and published.

## Preconditions

1. Two Linux VPS nodes (client/server roles).
2. Reachable metrics endpoints (`/metrics`, `/debug/pprof/*`).
3. Optional WARP-capable environment for underlay validation.

## Commands

1. Upstream snapshot audit:
   - `make upstream-audit`
2. Mode benchmark baseline gate:
   - `make benchmark-live TARGET=<vps-ip>`
3. Full mode matrix + WARP on/off:
   - `python3 tools/live_validation_runner.py validate-live --target <vps-ip> --warp both`
4. Full Phase 11 live gate on two VPS nodes (recommended, SSH orchestration):
   - `make validate-live-ssh GATEWAY_HOST=<gateway-ip> AGENT_HOST=<agent-ip> BUNDLE=dist/<stealthlink-zip> WARP=both`
4. Stress gate:
   - `make stress-live`
5. Soak gate (24h):
   - `make soak-24h`
6. Profiling capture:
   - `make profile-live`
7. Release-readiness summary:
   - `python3 tools/live_validation_runner.py release-readiness`

## Gate Behavior (Strict)

- `validate-live` fails unless every mode (`4a..4e`) has:
  - non-empty `metrics`,
  - non-empty acceptance `checks`,
  - acceptance `pass=true`.
- `stress-live` fails if any stress test command exits non-zero.
- `soak-24h` fails if any periodic probe exits non-zero.
- `profile-live` fails if pprof fetch fails or profile files are empty.

## Required Evidence Artifacts

Save all outputs from `dist/live-validation/`:

- `validate-live.json`
- `stress-live.json`
- `soak-24h.json`
- `profile-live.json`
- `release-readiness.json`
- pprof captures (`*-cpu.pb.gz`, `*-heap.pb.gz`)

## External Release Gate (Manual)

1. Create tag:
   - `git tag v2.0.0`
   - `git push origin v2.0.0`
2. Upload release ZIP(s) and `dist/grafana-dashboard.json`.
3. Publish release notes and announce.

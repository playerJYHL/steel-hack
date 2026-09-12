# Frontend Implementation

Implemented on `codex/frontend-redesign`, 2026-09-12. The UI stays Flask/Jinja,
vanilla JavaScript, and CSS. The design uses the prior MetaMask/Phantom review
for hierarchy and restrained event-driven motion, not copied wallet branding.

## Screens and controls

- Arena: defense-level radio tiles, channel selector, numbered payload editor,
  character count, copy/clear, handle input, searchable native-dialog example
  library, validation with preserved input, recent runs, and top-three results.
- Run: backend provenance, queue/running/final states, browser viewer, stable
  expandable step timeline, explicit recorded replay, payload/evidence, JSON
  export, fullscreen where supported, and prefilled iteration link.
- Leaderboard: ranked table, player search, level/model filters, current totals,
  pause/resume, and deferred reordering while the table is hovered or focused.
  Unknown model provenance is not included in the live-model filter.
- Spectator: the same run renderer follows the current/latest attack and clears
  all previous viewer, trace, evidence, score, and replay state on a run change.
- Missing-page state: clear 404 with a route back to the arena.

## Data path

```text
TargetAgent.on_step
  -> run_attack(..., on_progress=callback)
  -> QueueWorker -> Store.save_progress -> attacks.progress_json
  -> existing /api/attack/<id> and /api/latest polling
  -> shared RunView -> browser / trace / evidence / verdict
```

Snapshots contain `viewer_url`, `model_backend`, `sandbox_backend`, cumulative
`steps`, and `duration_ms`. They are published during setup and after completed
steps, not token-by-token or before a tool finishes. Scoring and final Contract B
remain authoritative. Progress callback failures are logged without skipping
scoring or cleanup. Final results clear progress, and late progress writes cannot
overwrite a terminal result. Existing SQLite databases gain one nullable column
on initialization; rows are retained.

There is no SSE transport migration. Browser UI polling is separate from the
Steel browser-control connection. This change does not replace the existing
agent tools or sandbox backend with Playwright or Browser Use.

Each poll has an 8-second timeout. Result/spectator polls normally use 1.2 seconds,
leaderboard polls 4 seconds; failures back off to 8 seconds. A final result stops
result-page polling. HTTP 404 stops a missing-run poll. HTTP errors and malformed
responses retry. Existing trace nodes and the same viewer iframe survive polls.

## Presentation integrity

The `scripted/local` badge describes the actual result, not a real LLM jailbreak.
The static image in `web/static/target-preview.png` is a Chrome capture of the
empty-payload `/scenario` page at 1000 x 680. It is labelled a task reference and
is never animated as if it were a live browser. Re-capture it if the base scenario
changes. No MetaMask or Phantom media is shipped in this application.

Steel viewer URLs are restricted to HTTP(S) without URL-embedded credentials.
The iframe has a title and no-referrer policy, and is mounted only when the URL
changes. Completed sessions say `SESSION ENDED`; replay is a replay of recorded
step data, not a guaranteed Steel video recording. Actual viewer availability
after release is controlled by Steel and still needs live-path verification.

User payloads, handles, errors, tool outputs, and evidence use escaped Jinja or
DOM `textContent`, never dynamic HTML injection.

## Motion and accessibility

Neutral charcoal/white surfaces use coral for triggers, cyan for active status,
lime for refusal, and amber for waiting. Text/icons accompany status color.
Controls use 150-160ms feedback, new events 200ms entrances, and final verdicts
one 350ms transition. No flashing, parallax, continuous spinner, decorative
video, or scroll-driven narrative is included. `prefers-reduced-motion` disables
CSS animation/transitions and smooth replay scrolling.

Native radio/select/dialog semantics, visible focus rings, a skip link,
labelled icon controls, focusable scroll regions, and bounded text surfaces are
included. On mobile, local runs put their meaningful activity trace before the
reference image. The leaderboard scrolls within its region, not the whole page.

## Verification on 2026-09-12

- Python: **97 passed**. Includes cumulative progress, failing callback cleanup,
  SQLite migration, final-result protection, queued progress exposed via the
  API, escaped validation input, retry preservation, and model provenance.
- Node DOM tests: **12 passed**, using jsdom. Covers stable trace nodes,
  safe text rendering, spectator state clearing, viewer reuse and URL validation,
  recorded replay, filtering/empty states, reconnect/backoff, 404 shutdown,
  example selection, and whitespace validation.
- Tripwire self-test: **9/9 routes caught and blocked**, scripted/local only.
- Chrome responsive audit: five screens at widths **320, 390, 768, 1024, 1440,
  and 1920**, with no page-level horizontal overflow, overflowing button labels,
  or broken images in the 30 checked layouts.
- axe-core 4.13.0: no detected WCAG 2 A/AA or 2.1 AA violations on those five
  main screens at the audited desktop state. Arena also checked at 390px.
  This is an automated check, not a complete accessibility conformance claim.
- Browser interaction checks: library selection and launch, native Escape and
  focus return, real scripted tripwire result, filtered level-three no-trigger
  result, trace replay/stop, reduced-motion styles, search, pause/resume, injected
  failed-fetch recovery followed by a real API response, and downloaded JSON
  parsed successfully from disk. No live Steel session or paid model call used.

The checked preview runs on `http://127.0.0.1:8082`, with its own
`runs/frontend/arena.db`, separate from the existing server on port 8080.
Untracked audit JSON and screenshots are in `runs/frontend/`; selected screenshots
are in this directory. Node dependencies are development-only:

```bash
python -m pytest -q
npm ci
npm run test:ui
python -m tripwire.fake_agent --self-test
```

## Remaining checks

Live Steel iframe loading, real-model progress cadence, released-session viewer
behavior, and cross-browser/screen-reader testing were not exercised here.
The implementation does not guarantee a live viewer will be reachable.

An existing scripted-backend limitation surfaced: a filtered/benign run can
repeat its summary-write command until the step budget is exhausted. The UI
therefore says `No tripwire triggered`, not `Task succeeded` or `Defended` unless
the backend actually reports refusal. That backend behavior and task-completion
evaluation are outside this frontend change and should be addressed separately.

Icons are locally vendored from `lucide-static` 1.45.0. Original licenses and
attribution are in `web/static/icons/LICENSE` and `README.md`.

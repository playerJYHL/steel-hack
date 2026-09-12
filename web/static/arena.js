"use strict";

const $ = (id) => document.getElementById(id);
const terminal = (row) => !!row && ["done", "error"].includes(row.status);
const reducedMotion = () =>
  window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const api = (path) => (document.body.dataset.apiRoot || "") + path;
const channels = {
  page_hidden_text: "Hidden page text",
  fake_system_block: "System notice",
  poisoned_tool_return: "Tool response",
};
const triggers = {
  exfil: "Exfiltration",
  destructive: "Destruction",
  cred_use: "Credential use",
};
const actions = {
  read_page: "Read research page",
  bash: "Shell command",
  http: "HTTP request",
  final: "Final response",
};

function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = String(text);
  return el;
}
function icon(name) {
  const el = node("span", "icon");
  el.setAttribute("aria-hidden", "true");
  el.style.setProperty(
    "--icon",
    `url("${document.body.dataset.staticRoot}icons/${name}.svg")`,
  );
  return el;
}
function setText(id, text) {
  const el = $(id);
  if (el && el.textContent !== String(text)) el.textContent = text;
}
function setButton(button, symbol, label) {
  button.replaceChildren(icon(symbol), document.createTextNode(` ${label}`));
}
let toastTimer;
function toast(message) {
  setText("toast", message);
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    $("toast").hidden = true;
  }, 3500);
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to clipboard");
  } catch {
    toast("Clipboard unavailable. Select the text to copy it.");
  }
}
function connection(message, state = "online") {
  setText("connection", message);
  if ($("connection")) $("connection").dataset.state = state;
}

// One request at a time, with timeout, bounded backoff, and terminal shutdown.
class Poller {
  constructor(url, receive, interval = 1200) {
    this.url = url;
    this.receive = receive;
    this.interval = interval;
    this.failures = 0;
    this.stopped = false;
  }
  async tick() {
    if (this.stopped) return;
    this.controller = new AbortController();
    const timeout = setTimeout(() => this.controller.abort(), 8000);
    let keepGoing = true;
    try {
      const response = await fetch(this.url, {
        cache: "no-store",
        signal: this.controller.signal,
      });
      if (this.stopped) return;
      if (response.status === 404) {
        connection("Unavailable", "offline");
        toast("This run is no longer available.");
        this.stop();
        return;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (this.stopped) return;
      this.failures = 0;
      connection("Connected");
      keepGoing = this.receive(data) !== false;
    } catch (error) {
      if (this.stopped) return;
      this.failures++;
      connection("Reconnecting", "offline");
    } finally {
      clearTimeout(timeout);
    }
    if (!keepGoing) this.stop();
    if (!this.stopped) {
      this.timer = setTimeout(
        () => this.tick(),
        Math.min(8000, this.interval * 2 ** this.failures),
      );
    }
  }
  start() {
    this.tick();
    return this;
  }
  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    this.controller?.abort();
  }
}

const ArenaForm = {
  init() {
    const form = $("attack-form"),
      payload = $("payload"),
      library = $("payload-library");
    const update = () => {
      setText(
        "payload-count",
        `${payload.value.length.toLocaleString()} / ${payload.maxLength.toLocaleString()}`,
      );
      payload.setCustomValidity("");
      $("form-error").hidden = true;
    };
    // Keep a server validation error visible until the user edits the payload.
    const hadError = !$("form-error").hidden;
    update();
    $("form-error").hidden = !hadError;
    payload.addEventListener("input", update);
    $("copy-payload").addEventListener("click", () => copyText(payload.value));
    $("clear-payload").addEventListener("click", () => {
      payload.value = "";
      update();
      payload.focus();
    });
    $("open-library").addEventListener("click", () => {
      library.showModal();
      $("library-search").focus();
    });
    $("close-library").addEventListener("click", () => library.close());
    library.addEventListener("click", (event) => {
      if (event.target !== library) return;
      const r = library.getBoundingClientRect();
      if (
        event.clientX < r.left ||
        event.clientX > r.right ||
        event.clientY < r.top ||
        event.clientY > r.bottom
      )
        library.close();
    });
    const starters = [...document.querySelectorAll(".starter")];
    $("library-search").addEventListener("input", (event) => {
      const query = event.target.value.toLowerCase().trim();
      starters.forEach((button) => {
        button.hidden = !button.textContent.toLowerCase().includes(query);
      });
      $("library-empty").hidden = starters.some((button) => !button.hidden);
    });
    starters.forEach((button) =>
      button.addEventListener("click", () => {
        payload.value = button.dataset.text;
        $(`level-${button.dataset.level}`).checked = true;
        $("vector").value = button.dataset.vector;
        update();
        library.close();
        payload.focus();
      }),
    );
    form.addEventListener("submit", (event) => {
      if (!payload.value.trim()) {
        event.preventDefault();
        setText("form-error", "Add a payload before launching.");
        $("form-error").hidden = false;
        payload.focus();
        return;
      }
      $("launch").disabled = true;
      $("launch").setAttribute("aria-busy", "true");
      setButton($("launch"), "clock-3", "Launching");
    });
    window.addEventListener("pageshow", () => {
      $("launch").disabled = false;
      $("launch").removeAttribute("aria-busy");
      setButton($("launch"), "arrow-up-right", "Launch attack");
    });
  },
};

function verdictFor(row) {
  if (!row?.attack_id)
    return {
      state: "queued",
      icon: "clock-3",
      title: "Waiting for an attack",
      detail: "The arena is ready.",
    };
  if (row.status === "queued")
    return {
      state: "queued",
      icon: "clock-3",
      title: "In the queue",
      detail:
        row.position == null
          ? "Waiting for the current run to finish."
          : `${row.position} ahead of this attempt. One agent runs at a time.`,
    };
  if (row.status === "running")
    return {
      state: "running",
      icon: "scan-line",
      title: "Agent is running",
      detail: "The task is in progress. No final verdict yet.",
    };
  const r = row.result || {};
  if (r.triggered)
    return {
      state: "triggered",
      icon: "crosshair",
      title: "Tripwire triggered.",
      detail: `${triggers[r.trigger_type] || r.trigger_type || "Forbidden action"}${r.step_index != null ? ` at step ${r.step_index}` : ""}. Deterministic evidence recorded.${r.error ? ` Run warning: ${r.error}` : ""}`,
    };
  if (row.status === "error" || r.error)
    return {
      state: "error",
      icon: "circle-alert",
      title: "Run interrupted",
      detail: r.error || "The run could not finish. Retry with a new attempt.",
    };
  if (r.defended)
    return {
      state: "defended",
      icon: "shield-check",
      title: "Boundary held.",
      detail: "The agent read the injection and refused.",
    };
  return {
    state: "done",
    icon: "check",
    title: "No tripwire triggered",
    detail: "The run ended without a detected forbidden action.",
  };
}

function renderTrace(el, result) {
  // Follow the stream: if the viewer is already near the bottom, keep the
  // latest step in view after this update. If they scrolled up to read an
  // earlier step, leave their position alone.
  const scroll = el.parentElement;
  const stick = scroll
    ? scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 40
    : false;
  const steps = result?.steps || [];
  const wanted = new Set();
  for (const step of steps) {
    const key = String(step.i);
    wanted.add(key);
    let li = [...el.children].find((child) => child.dataset.step === key);
    const isTrip = result.step_index != null && step.i === result.step_index;
    const signature = JSON.stringify([step, isTrip]);
    if (!li) {
      li = node("li");
      li.dataset.step = key;
      el.append(li);
    }
    if (li.dataset.signature === signature) continue;
    const wasOpen = li.querySelector("details")?.open || false;
    li.dataset.signature = signature;
    li.classList.toggle("trip", isTrip);
    const title = node("div", "step-title");
    title.append(
      node("strong", "", actions[step.action] || step.action),
      node("span", "step-index", `STEP ${step.i}`),
    );
    const content = [title];
    if (isTrip)
      content.push(node("p", "step-thought triggered", "Tripwire fired"));
    if (step.thought) content.push(node("p", "step-thought", step.thought));
    if (step.output || Object.keys(step.tool_input || {}).length) {
      const details = node("details");
      details.open = wasOpen;
      details.append(
        node("summary", "", "Input / output"),
        node(
          "pre",
          "",
          [
            Object.keys(step.tool_input || {}).length
              ? JSON.stringify(step.tool_input, null, 2)
              : "",
            step.output || "",
          ]
            .filter(Boolean)
            .join("\n\n"),
        ),
      );
      details.querySelector("pre").tabIndex = 0;
      content.push(details);
    }
    li.replaceChildren(...content);
  }
  [...el.children].forEach((child) => {
    if (!wanted.has(child.dataset.step)) child.remove();
  });
  // Instant jump (no smooth) so it is correct under prefers-reduced-motion.
  if (scroll && stick) scroll.scrollTop = scroll.scrollHeight;
}

function safeViewerUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) &&
      !url.username &&
      !url.password
      ? url.href
      : null;
  } catch {
    return null;
  }
}

// Embed viewers read-only: viewers watch, they never grab control of the session.
function embedViewerUrl(value) {
  try {
    const url = new URL(value);
    if (!url.searchParams.has("interactive"))
      url.searchParams.set("interactive", "false");
    return url.href;
  } catch {
    return value;
  }
}

// Mode-agnostic label for the session: a Steel Browser and a Steel Computer both
// expose the same viewer_url, so the page never hardcodes one or the other.
function sessionModeLabel(mode, sandbox, hasUrl) {
  if (mode) return String(mode).toUpperCase();
  if (sandbox === "local") return "LOCAL";
  return hasUrl ? "CLOUD SESSION" : "CLOUD";
}

class RunView {
  constructor() {
    this.lastId = null;
    this.viewerUrl = null;
    this.idleMode = null;
    this.reference = $("liveview").firstElementChild.cloneNode(true);
    this.row = null;
    // "The moment": fire the dramatic overlay once, only for a run we watched
    // reach its verdict (or always, on the spectator big screen).
    this.watched = false;
    this.momentKey = null;
    this.overlayTimer = null;
    this.spectator = $("run-surface")?.dataset.view === "spectator";
    this.initOverlay();
    $("copy-run-payload").addEventListener("click", () =>
      copyText(this.row?.payload || ""),
    );
    $("export-run").addEventListener("click", () => {
      if (!this.row) return;
      const blob = new Blob([JSON.stringify(this.row, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const link = node("a");
      link.href = url;
      link.download = `arena-${this.row.attack_id}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    $("replay-trace").addEventListener("click", () => this.replay());
    $("fullscreen").hidden = !document.fullscreenEnabled;
    $("fullscreen").addEventListener("click", async () => {
      try {
        if (document.fullscreenElement) await document.exitFullscreen();
        else await $("run-surface").requestFullscreen();
      } catch {
        toast("Fullscreen is not available in this browser.");
      }
    });
  }
  initOverlay() {
    const overlay = $("run-overlay");
    if (!overlay) return;
    $("overlay-dismiss")?.addEventListener("click", () => this.hideOverlay());
    $("overlay-continue")?.addEventListener("click", () => {
      this.hideOverlay();
      const target = $("evidence").hidden ? $("run-payload") : $("evidence");
      target?.scrollIntoView({
        behavior: reducedMotion() ? "auto" : "smooth",
        block: "center",
      });
    });
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) this.hideOverlay();
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !overlay.hidden) this.hideOverlay();
    });
  }
  hideOverlay() {
    const overlay = $("run-overlay");
    clearTimeout(this.overlayTimer);
    if (overlay && !overlay.hidden) overlay.hidden = true;
  }
  syncMoment(state, result, row) {
    const overlay = $("run-overlay");
    if (!overlay) return;
    const dramatic = ["triggered", "defended", "done"].includes(state);
    if (!dramatic) {
      this.hideOverlay();
      return;
    }
    const key = `${row?.attack_id || ""}:${state}`;
    // Fire once. Live flow: only after we watched it run. Spectator: always.
    if (key === this.momentKey) return;
    if (!this.watched && !this.spectator) {
      this.momentKey = key; // acknowledge without the alarm on a cold load
      return;
    }
    this.momentKey = key;
    this.showMoment(state, result);
  }
  showMoment(state, result) {
    const overlay = $("run-overlay");
    if (!overlay) return;
    const breach = state === "triggered";
    overlay.dataset.mode = breach ? "breach" : "held";
    const evidenceBox = $("overlay-evidence");
    if (breach) {
      const kind = triggers[result.trigger_type] || result.trigger_type || "Forbidden action";
      setText("overlay-kicker", "SECURITY BREACH");
      setText("overlay-title", "COMPROMISED");
      setText(
        "overlay-sub",
        "The agent read the planted instruction, believed it was the task, and carried out a forbidden action.",
      );
      setText("overlay-trigger", kind);
      setText(
        "overlay-step",
        result.step_index != null ? `at step ${result.step_index}` : "",
      );
      const ev = result.evidence || {};
      const snippet = ev.evidence || "";
      if (evidenceBox) evidenceBox.hidden = !snippet;
      if (snippet) {
        setText("overlay-evidence-surface", String(ev.surface || "surface").toUpperCase());
        setText("overlay-evidence-enc", ev.encoding || "plaintext");
        setText("overlay-evidence-snippet", snippet);
      }
    } else {
      const defended = !!result.defended;
      setText("overlay-kicker", "AGENT HELD");
      setText("overlay-title", defended ? "RESISTED" : "HELD THE LINE");
      setText(
        "overlay-sub",
        defended
          ? "The agent recognised the planted text as untrusted content and refused to act on it."
          : "The run finished with no forbidden action — none of the tripwires fired.",
      );
      setText("overlay-trigger", defended ? "Injection refused" : "No trigger");
      setText("overlay-step", "");
      if (evidenceBox) evidenceBox.hidden = true;
    }
    overlay.hidden = false;
    try {
      $("overlay-dismiss")?.focus({ preventScroll: true });
    } catch {
      /* focus is best-effort */
    }
    clearTimeout(this.overlayTimer);
    // The breach lingers until dismissed; the calm state clears itself.
    if (!breach)
      this.overlayTimer = setTimeout(() => this.hideOverlay(), 6500);
  }
  stopReplay() {
    clearTimeout(this.replayTimer);
    this.replaying = false;
    $("trace")
      .querySelectorAll(".replay-active")
      .forEach((el) => el.classList.remove("replay-active"));
    setButton($("replay-trace"), "play", "Replay");
    $("replay-state").hidden = true;
  }
  replay() {
    if (this.replaying) {
      this.stopReplay();
      return;
    }
    const steps = [...$("trace").children];
    if (!terminal(this.row) || !steps.length) return;
    this.replaying = true;
    setButton($("replay-trace"), "pause", "Stop replay");
    $("replay-state").hidden = false;
    let index = 0;
    const advance = () => {
      steps.forEach((el) => el.classList.remove("replay-active"));
      if (index >= steps.length) {
        this.stopReplay();
        toast("Recorded trace replay complete");
        return;
      }
      const current = steps[index++];
      current.classList.add("replay-active");
      if (!reducedMotion()) {
        const scroll = $("trace").parentElement;
        scroll.scrollTo({
          top: current.offsetTop - $("trace").offsetTop,
          behavior: "smooth",
        });
      }
      setText(
        "replay-state",
        `Recorded trace: step ${index} of ${steps.length}`,
      );
      this.replayTimer = setTimeout(advance, 1500);
    };
    advance();
  }
  render(row) {
    const id = row?.attack_id || null;
    if (id !== this.lastId) {
      this.stopReplay();
      this.hideOverlay();
      $("trace").replaceChildren();
      $("liveview").replaceChildren(this.reference.cloneNode(true));
      this.viewerUrl = null;
      this.idleMode = null;
      this.lastId = id;
      this.lastState = null;
      this.watched = false;
      this.momentKey = null;
      $("trace").parentElement.scrollTop = 0;
    }
    this.row = row;
    const v = verdictFor(row);
    if (["queued", "running"].includes(v.state)) this.watched = true;
    const strip = $("verdict-strip");
    strip.dataset.state = v.state;
    const surface = $("run-surface");
    if (surface) surface.dataset.state = v.state;
    if (this.lastState !== v.state) {
      $("verdict-icon").replaceChildren(icon(v.icon));
      strip.classList.remove("verdict-arrival");
      if (["triggered", "defended", "error"].includes(v.state)) {
        void strip.offsetWidth;
        strip.classList.add("verdict-arrival");
      }
      this.lastState = v.state;
    }
    setText("verdict", v.title);
    setText("verdict-detail", v.detail);
    const r = (terminal(row) ? row.result : row?.progress) || {};
    const model =
      r.model_backend ||
      (terminal(row) ? "unknown" : document.body.dataset.model);
    const sandbox =
      r.sandbox_backend ||
      (terminal(row) ? "unknown" : document.body.dataset.sandbox);
    setText(
      "verdict-kicker",
      `${terminal(row) ? "FINAL VERDICT" : "RUN STATUS"}${model === "scripted" ? " / TEST HARNESS" : ""}`,
    );
    setText("run-score", terminal(row) ? (r.score ?? 0) : "-");
    setText(
      "run-meta",
      id
        ? `Level ${row.level} / ${channels[row.vector] || row.vector} / ${row.player} / ${model} + ${sandbox}`
        : "No active run",
    );
    setText("run-payload", row?.payload || "Waiting for a submission.");
    setText(
      "payload-author",
      id ? `By ${row.player} / ${id.slice(0, 8)}` : "No submission",
    );
    $("export-run").disabled = !terminal(row);
    $("replay-trace").disabled = !terminal(row) || !r.steps?.length;
    renderTrace($("trace"), r);
    $("trace-empty").hidden = !!r.steps?.length;
    setText(
      "trace-status",
      `${r.steps?.length || 0} steps${terminal(row) ? " / recorded" : ""}`,
    );
    const elapsed =
      row?.status === "running" && row.started_at
        ? Date.now() - row.started_at * 1000
        : r.duration_ms || 0;
    setText("run-duration", `${(Math.max(0, elapsed) / 1000).toFixed(1)}s`);
    const hasEvidence =
      Object.keys(r.evidence || {}).length || r.tripwire_events?.length;
    $("evidence").hidden = !hasEvidence;
    $("evidence-empty").hidden = !!hasEvidence;
    setText(
      "evidence",
      hasEvidence
        ? JSON.stringify(
            { evidence: r.evidence || {}, events: r.tripwire_events || [] },
            null,
            2,
          )
        : "",
    );
    setText(
      "evidence-empty",
      terminal(row)
        ? "No tripwire evidence recorded."
        : "No tripwire evidence yet.",
    );
    this.mountViewer(safeViewerUrl(r.viewer_url), {
      sandbox,
      status: row?.status,
      state: v.state,
      mode: r.mode,
    });
    this.syncMoment(v.state, r, row);
  }
  mountViewer(url, options) {
    const { sandbox, status, state, mode } = options || {};
    const ended = ["done", "error"].includes(status);
    const active = ["queued", "running"].includes(status);
    const local = sandbox === "local";
    const connecting = !url && !local && active;
    if (url !== this.viewerUrl) {
      if (url) {
        const frame = node("iframe");
        frame.title = "Live session viewer";
        frame.referrerPolicy = "no-referrer";
        frame.allow = "fullscreen";
        frame.src = embedViewerUrl(url); // read-only embed
        $("liveview").replaceChildren(frame);
        this.idleMode = null;
      } else {
        this.idleMode = null;
        $("liveview").replaceChildren(this.idleNode(connecting));
      }
      this.viewerUrl = url;
    } else if (!url) {
      // No session yet: swap the placeholder only when its nature changes.
      const wanted = connecting ? "connecting" : "reference";
      if (this.idleMode !== wanted)
        $("liveview").replaceChildren(this.idleNode(connecting));
    }
    const open = $("open-viewer");
    open.hidden = !url;
    if (url) open.href = url;
    else open.removeAttribute("href");
    setText(
      "browser-address",
      url
        ? new URL(url).hostname
        : connecting
          ? "Provisioning session"
          : "Task page reference",
    );
    setText(
      "viewer-mode",
      local
        ? "LOCAL SIMULATION"
        : url
          ? ended
            ? "SESSION ENDED"
            : "LIVE SESSION"
          : connecting
            ? "CONNECTING"
            : "TASK REFERENCE",
    );
    setText(
      "viewer-description",
      local
        ? "Reference image only. The local sandbox has no live stream."
        : url
          ? ended
            ? "Session released. Viewer availability is managed by Steel."
            : "Live Steel session. The agent's steps stream alongside."
          : connecting
            ? "Booting the cloud session. The live view mounts the moment it is ready."
            : "Reference image only. Waiting for a live session.",
    );
    const pill = $("live-pill");
    if (pill) {
      let key = "idle";
      let label = "STANDBY";
      if (state === "triggered") {
        key = "breach";
        label = "BREACH";
      } else if (url && active) {
        key = "live";
        label = "LIVE";
      } else if (connecting) {
        key = "connecting";
        label = "CONNECTING";
      } else if (state === "defended") {
        key = "ended";
        label = "HELD";
      } else if (url && ended) {
        key = "ended";
        label = "ENDED";
      }
      pill.dataset.live = key;
      pill.textContent = label;
      pill.hidden = local;
    }
    setText("session-mode", sessionModeLabel(mode, sandbox, !!url));
  }
  idleNode(connecting) {
    if (connecting) {
      this.idleMode = "connecting";
      const wrap = node("div", "viewer-connecting");
      const radar = node("div", "radar");
      radar.append(icon("radio"));
      wrap.append(
        radar,
        node("strong", "", "Connecting to the cloud session"),
        node(
          "span",
          "",
          "Provisioning an isolated Steel session. The live view appears here the moment the agent boots.",
        ),
      );
      return wrap;
    }
    this.idleMode = "reference";
    return this.reference.cloneNode(true);
  }
}

const ArenaResult = {
  init(attackId) {
    const view = new RunView();
    const initial = $("initial-run");
    if (initial) view.render(JSON.parse(initial.textContent));
    return new Poller(
      api(`/api/attack/${encodeURIComponent(attackId)}`),
      (row) => {
        view.render(row);
        if (terminal(row)) {
          connection("Recorded run");
          return false;
        }
      },
    ).start();
  },
};
const ArenaDemo = {
  init() {
    const view = new RunView();
    return new Poller(api("/api/latest"), (row) => view.render(row)).start();
  },
};

function renderBoard(data, filters = {}) {
  const rows = (data.board || [])
    .map((row, index) => ({ ...row, rank: index + 1 }))
    .filter((row) => {
      const model = row.model_backend || "unknown";
      return (
        (!filters.query ||
          row.player.toLowerCase().includes(filters.query.toLowerCase())) &&
        (!filters.level || String(row.level) === filters.level) &&
        (!filters.backend ||
          (filters.backend === "scripted"
            ? model === "scripted"
            : !["scripted", "unknown"].includes(model)))
      );
    });
  const body = $("lb-body");
  const signature = JSON.stringify(rows);
  if (body.dataset.signature !== signature) {
    const previous = new Set(
      [...body.querySelectorAll("tr[data-attack]")].map(
        (tr) => tr.dataset.attack,
      ),
    );
    body.dataset.signature = signature;
    const fragment = document.createDocumentFragment();
    rows.forEach((row) => {
      const tr = node("tr");
      tr.dataset.attack = row.attack_id;
      if (previous.size && !previous.has(row.attack_id))
        tr.classList.add("new-ranked");
      const player = node("td");
      player.append(
        node("strong", "", row.player),
        node(
          "span",
          "backend-label",
          `${row.model_backend || "unknown"} / ${row.sandbox_backend || "unknown"}`,
        ),
      );
      const level = node("td");
      level.append(node("span", "level-token", `L${row.level}`));
      const trip = node("td");
      trip.append(
        node(
          "span",
          "status-label triggered",
          triggers[row.trigger_type] || row.trigger_type,
        ),
      );
      const link = node("a", "icon-button");
      link.href = api(`/attack/${encodeURIComponent(row.attack_id)}`);
      link.title = `View run by ${row.player}`;
      link.setAttribute("aria-label", link.title);
      link.append(icon("arrow-up-right"));
      const run = node("td");
      run.append(link);
      tr.append(
        node("td", "rank", String(row.rank).padStart(2, "0")),
        player,
        level,
        node("td", "", channels[row.vector] || row.vector),
        trip,
        node("td", "", row.steps),
        node("td", "score", row.score),
        run,
      );
      fragment.append(tr);
    });
    if (!rows.length) {
      const tr = node("tr"),
        td = node("td"),
        empty = node("div", "board-empty");
      td.colSpan = 8;
      empty.append(
        icon("trophy"),
        node(
          "h2",
          "",
          data.board?.length ? "No matching runs" : "An open field.",
        ),
        node(
          "p",
          "",
          data.board?.length
            ? "No ranked runs match these filters."
            : "No tripwires triggered yet.",
        ),
      );
      td.append(empty);
      tr.append(td);
      fragment.append(tr);
    }
    body.replaceChildren(fragment);
  }
  setText(
    "board-count",
    `${rows.length} of ${(data.board || []).length} ranked runs`,
  );
  const stats = data.stats || {};
  for (const key of ["total", "wins", "queued"])
    setText(`stat-${key}`, stats[key] ?? 0);
  for (let level = 1; level <= 4; level++)
    setText(`stat-level-${level}`, stats.wins_by_level?.[level] ?? 0);
}

const ArenaBoard = {
  init() {
    let latest = JSON.parse($("initial-board").textContent);
    let paused = false,
      hovered = false;
    const table = document.querySelector(".table-scroll");
    const filters = () => ({
      query: $("board-search").value.trim(),
      level: $("level-filter").value,
      backend: $("backend-filter").value,
    });
    const render = () => renderBoard(latest, filters());
    const held = () =>
      paused || hovered || table.contains(document.activeElement);
    const applyPending = () => {
      if (!held()) render();
    };
    ["board-search", "level-filter", "backend-filter"].forEach((id) =>
      $(id).addEventListener("input", render),
    );
    table.addEventListener("pointerenter", (event) => {
      if (event.pointerType !== "touch") hovered = true;
    });
    table.addEventListener("pointerleave", () => {
      hovered = false;
      applyPending();
    });
    table.addEventListener("focusout", () => setTimeout(applyPending, 0));
    $("pause-board").addEventListener("click", () => {
      paused = !paused;
      const button = $("pause-board");
      button.setAttribute("aria-pressed", String(paused));
      button.setAttribute(
        "aria-label",
        paused ? "Resume updates" : "Pause updates",
      );
      button.title = button.getAttribute("aria-label");
      button.replaceChildren(icon(paused ? "play" : "pause"));
      connection(paused ? "Paused" : "Connected");
      if (!paused) applyPending();
    });
    render();
    return new Poller(
      api("/api/leaderboard"),
      (data) => {
        latest = data;
        if (held()) connection(paused ? "Paused" : "Updates held");
        else render();
      },
      4000,
    ).start();
  },
};

if (typeof module !== "undefined")
  module.exports = {
    Poller,
    RunView,
    verdictFor,
    renderTrace,
    renderBoard,
    safeViewerUrl,
    ArenaForm,
  };

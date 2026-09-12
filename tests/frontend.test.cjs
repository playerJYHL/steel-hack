const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { JSDOM } = require("jsdom");
const {
  Poller,
  RunView,
  verdictFor,
  renderTrace,
  renderBoard,
  safeViewerUrl,
  ArenaForm,
} = require("../web/static/arena.js");

let dom;
function mount(html = "") {
  dom = new JSDOM(
    `<body data-static-root="/static/" data-model="scripted" data-sandbox="local">${html}<div id="toast" hidden></div></body>`,
    { url: "http://localhost:8082" },
  );
  global.document = dom.window.document;
  global.window = dom.window;
  window.matchMedia = () => ({ matches: true });
  return document;
}
afterEach(() => {
  dom?.window.close();
});

function runFixture() {
  mount(`<div id="run-surface"><div id="liveview"><div class="viewer-reference"><img alt="Reference"></div></div>
    <div id="trace-container"><ol id="trace"></ol></div>
    ${["copy-run-payload", "export-run", "replay-trace", "fullscreen"].map((id) => `<button id="${id}"></button>`).join("")}
    ${["verdict-strip", "verdict-icon", "verdict", "verdict-detail", "verdict-kicker", "run-score", "run-meta", "run-payload", "payload-author", "trace-empty", "trace-status", "run-duration", "evidence", "evidence-empty", "browser-address", "viewer-mode", "viewer-description", "replay-state", "connection"].map((id) => `<div id="${id}"></div>`).join("")}
    <a id="open-viewer"></a></div>`);
}
const step = {
  i: 0,
  action: "read_page",
  thought: "Reading",
  output: "Article",
  tool_input: { url: "http://localhost/page.html" },
};
const row = {
  attack_id: "one",
  status: "done",
  player: "Simon",
  level: 1,
  vector: "page_hidden_text",
  payload: "payload",
  result: {
    triggered: true,
    trigger_type: "exfil",
    step_index: 0,
    score: 115,
    steps: [step],
    model_backend: "scripted",
    sandbox_backend: "local",
    duration_ms: 100,
    evidence: { surface: "http" },
  },
};

test("verdict respects active state before stale result data", () => {
  assert.equal(verdictFor({ ...row, status: "running" }).state, "running");
  assert.equal(
    verdictFor({ ...row, status: "queued", position: 2 }).state,
    "queued",
  );
  assert.equal(verdictFor(row).state, "triggered");
  assert.equal(
    verdictFor({ ...row, result: { defended: true } }).state,
    "defended",
  );
  assert.equal(
    verdictFor({ ...row, status: "error", result: { error: "network" } }).state,
    "error",
  );
});

test("stable trace nodes preserve expansion across polls", () => {
  mount('<ol id="trace"></ol>');
  const trace = document.getElementById("trace");
  renderTrace(trace, { steps: [step] });
  const first = trace.firstChild;
  first.querySelector("details").open = true;
  renderTrace(trace, { steps: [step, { ...step, i: 1 }] });
  assert.equal(trace.firstChild, first);
  assert.equal(first.querySelector("details").open, true);
  renderTrace(trace, { steps: [step], step_index: 0 });
  assert.equal(first.querySelector("details").open, true);
  assert.equal(trace.children.length, 1);
  assert.equal(first.classList.contains("trip"), true);
});

test("payloads and model outputs are rendered as text, not HTML", () => {
  runFixture();
  const injection = "<img src=x onerror=alert(1)><script>alert(2)</script>";
  const view = new RunView();
  view.render({
    ...row,
    payload: injection,
    result: {
      ...row.result,
      steps: [{ ...step, thought: injection, output: injection }],
    },
  });
  assert.equal(document.getElementById("run-payload").textContent, injection);
  assert.equal(document.querySelector("#trace img, #trace script"), null);
});

test("new spectator run clears old viewer, trace, evidence and score", () => {
  runFixture();
  const view = new RunView();
  view.render({
    ...row,
    result: {
      ...row.result,
      viewer_url: "https://example.com/one",
      sandbox_backend: "steel",
    },
  });
  assert.ok(document.querySelector("#liveview iframe"));
  view.render({
    ...row,
    attack_id: "two",
    status: "running",
    result: undefined,
    progress: {
      steps: [],
      sandbox_backend: "local",
      model_backend: "scripted",
    },
  });
  assert.equal(document.querySelector("#liveview iframe"), null);
  assert.equal(document.querySelectorAll("#trace>li").length, 0);
  assert.equal(document.getElementById("evidence").textContent, "");
  assert.equal(document.getElementById("evidence").hidden, true);
  assert.equal(document.getElementById("run-score").textContent, "-");
  assert.equal(
    document.getElementById("open-viewer").hasAttribute("href"),
    false,
  );
});

test("same live viewer is not remounted at each progress update", () => {
  runFixture();
  const view = new RunView();
  const active = {
    ...row,
    status: "running",
    progress: {
      steps: [],
      viewer_url: "https://example.com/view",
      sandbox_backend: "steel",
    },
  };
  view.render(active);
  const frame = document.querySelector("iframe");
  view.render({ ...active, progress: { ...active.progress, steps: [step] } });
  assert.equal(document.querySelector("iframe"), frame);
  assert.equal(
    document.getElementById("viewer-mode").textContent,
    "LIVE SESSION",
  );
  view.render({
    ...row,
    result: {
      ...row.result,
      viewer_url: "https://example.com/view",
      sandbox_backend: "steel",
    },
  });
  assert.equal(
    document.getElementById("viewer-mode").textContent,
    "SESSION ENDED",
  );
});

test("viewer URL rejects executable and credential-bearing schemes", () => {
  for (const bad of [
    "javascript:alert(1)",
    "data:text/html,test",
    "file:///etc/passwd",
    "https://user:pass@example.com",
    "not a URL",
  ])
    assert.equal(safeViewerUrl(bad), null);
  assert.equal(
    safeViewerUrl("https://example.com/view"),
    "https://example.com/view",
  );
});

test("recorded trace replay starts and can be stopped without changing verdict", () => {
  runFixture();
  const view = new RunView();
  view.render(row);
  view.replay();
  assert.equal(document.querySelectorAll(".replay-active").length, 1);
  assert.equal(document.getElementById("replay-state").hidden, false);
  view.replay();
  assert.equal(document.querySelectorAll(".replay-active").length, 0);
  assert.equal(
    document.getElementById("verdict").textContent,
    "Tripwire triggered.",
  );
});

function boardFixture() {
  mount(
    `<table><tbody id="lb-body"></tbody></table>${["board-count", "stat-total", "stat-wins", "stat-queued", "stat-level-1", "stat-level-2", "stat-level-3", "stat-level-4"].map((id) => `<span id="${id}"></span>`).join("")}`,
  );
}
test("leaderboard filters preserve rank and exclude unknown from live models", () => {
  boardFixture();
  const base = {
    attack_id: "a",
    player: "Simon",
    level: 2,
    vector: "page_hidden_text",
    score: 200,
    steps: 2,
    trigger_type: "exfil",
    sandbox_backend: "local",
  };
  const data = {
    board: [
      { ...base, model_backend: "scripted" },
      { ...base, model_backend: "unknown" },
      { ...base, model_backend: "anthropic" },
    ],
    stats: { wins: 3, total: 4 },
  };
  renderBoard(data, { backend: "live", query: "simon", level: "2" });
  assert.equal(document.querySelectorAll("#lb-body tr").length, 1);
  assert.equal(document.querySelector(".rank").textContent, "03");
  assert.match(document.querySelector("#lb-body").textContent, /anthropic/);
  assert.equal(document.getElementById("stat-total").textContent, "4");
});

test("leaderboard clears stale rows when it becomes empty", () => {
  boardFixture();
  renderBoard({
    board: [
      {
        attack_id: "a",
        player: "<script>x</script>",
        score: 100,
        steps: 1,
        level: 1,
        vector: "page_hidden_text",
      },
    ],
  });
  assert.equal(document.querySelector("#lb-body script"), null);
  renderBoard({ board: [], stats: {} });
  assert.match(document.querySelector("#lb-body").textContent, /An open field/);
  assert.equal(document.querySelector("#lb-body a"), null);
});

test("poller retries failures with backoff and stops after a final response", async (t) => {
  mount('<span id="connection"></span>');
  const scheduled = [];
  t.mock.method(global, "setTimeout", (callback, delay) => {
    scheduled.push({ callback, delay });
    return scheduled.length;
  });
  t.mock.method(global, "clearTimeout", () => {});
  let request = 0;
  t.mock.method(global, "fetch", async () => {
    if (!request++) throw new Error("offline");
    return { ok: true, status: 200, json: async () => row };
  });
  const poller = new Poller(
    "/api/test",
    (data) => {
      assert.equal(data.attack_id, "one");
      return false;
    },
    1000,
  );
  await poller.tick();
  assert.equal(
    document.getElementById("connection").textContent,
    "Reconnecting",
  );
  assert.equal(scheduled.at(-1).delay, 2000);
  await scheduled.at(-1).callback();
  assert.equal(poller.stopped, true);
  assert.equal(poller.failures, 0);
});

test("poller treats a missing run as unavailable and does not spin forever", async (t) => {
  mount('<span id="connection"></span>');
  t.mock.method(global, "setTimeout", () => 1);
  t.mock.method(global, "clearTimeout", () => {});
  t.mock.method(global, "fetch", async () => ({ status: 404, ok: false }));
  const poller = new Poller("/missing", () => assert.fail("not data"));
  await poller.tick();
  assert.equal(poller.stopped, true);
  assert.equal(
    document.getElementById("connection").textContent,
    "Unavailable",
  );
});

test("form restores examples and blocks whitespace submissions", () => {
  mount(`<form id="attack-form"><textarea id="payload" maxlength="8000"></textarea><input type="radio" id="level-2"><select id="vector"><option value="fake_system_block"></option></select><button id="launch"></button></form>
    <div id="payload-count"></div><div id="line-numbers"></div><p id="form-error" hidden></p>
    <button id="copy-payload"></button><button id="clear-payload"></button><button id="open-library"></button>
    <dialog id="payload-library"><button id="close-library"></button><input id="library-search"><button class="starter" data-text="Example payload" data-level="2" data-vector="fake_system_block">Example</button><p id="library-empty" hidden></p></dialog>`);
  document.getElementById("payload-library").close = () => {};
  ArenaForm.init();
  document.querySelector(".starter").click();
  assert.equal(document.getElementById("payload").value, "Example payload");
  assert.equal(document.getElementById("level-2").checked, true);
  assert.equal(document.getElementById("vector").value, "fake_system_block");
  const payload = document.getElementById("payload");
  payload.value = "   ";
  const event = new window.Event("submit", { cancelable: true });
  document.getElementById("attack-form").dispatchEvent(event);
  assert.equal(event.defaultPrevented, true);
  assert.equal(document.getElementById("form-error").hidden, false);
  assert.equal(document.getElementById("launch").disabled, false);
});

/* Front-end for the arena. No framework — the pages are simple and the booth
   network can't be trusted to pull a CDN, so everything is one vanilla file.
   Three controllers: the submission form, the live result page, the big screen. */
"use strict";

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

/* Prefill the form from a starter payload in the library. */
const ArenaForm = {
  init() {
    document.querySelectorAll(".starter").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelector("textarea[name=payload]").value = btn.dataset.text;
        document.querySelector("select[name=level]").value = btn.dataset.level;
        document.querySelector("select[name=vector]").value = btn.dataset.vector;
        document.querySelector("textarea[name=payload]").scrollIntoView({ behavior: "smooth" });
      });
    });
  },
};

/* Render one attack's state into a verdict + trace. Shared by the result page
   and the demo screen so they can never show a run differently. */
function renderTrace(el, result) {
  el.innerHTML = "";
  const steps = (result && result.steps) || [];
  const tripAt = result ? result.step_index : null;
  steps.forEach(s => {
    const li = document.createElement("li");
    if (tripAt !== null && s.i === tripAt) li.className = "trip";
    li.innerHTML =
      `<div class="act">${esc(s.action)}${(tripAt !== null && s.i === tripAt) ? " · tripwire fired" : ""}</div>` +
      (s.thought ? `<div class="thought">${esc(s.thought)}</div>` : "") +
      (s.tool_input && Object.keys(s.tool_input).length
        ? `<div class="out">${esc(JSON.stringify(s.tool_input))}</div>` : "") +
      (s.output ? `<div class="out">${esc(s.output)}</div>` : "");
    el.appendChild(li);
  });
}

function verdictFor(row) {
  if (!row || !row.result) {
    const st = row ? row.status : "queued";
    if (st === "queued") return { cls: "", text: `Queued — position ${row ? row.position : "?"}` };
    if (st === "running") return { cls: "", text: "Agent is running…", spin: true };
    return { cls: "", text: "…" };
  }
  const r = row.result;
  if (r.error && !r.triggered) return { cls: "", text: "Run failed: " + esc(r.error) };
  if (r.triggered) {
    const at = r.step_index !== null ? ` at step ${r.step_index}` : "";
    return { cls: "win", text: `TRIGGERED — ${esc(r.trigger_type)}${at}. Score ${r.score}.` };
  }
  if (r.defended) return { cls: "defended", text: "The agent read the injection and refused." };
  return { cls: "safe", text: "No trigger — the agent stayed on task." };
}

function mountLiveview(el, row) {
  const url = row && row.result && row.result.viewer_url;
  if (url && el && !el.dataset.mounted) {
    el.dataset.mounted = "1";
    el.innerHTML = `<iframe src="${esc(url)}" allow="fullscreen"></iframe>`;
  }
}

const ArenaResult = {
  init(attackId) {
    const verdict = document.getElementById("verdict");
    const trace = document.getElementById("trace");
    const evidence = document.getElementById("evidence");
    const liveview = document.getElementById("liveview");
    const status = document.getElementById("trace-status");

    const poll = async () => {
      let row;
      try {
        row = await (await fetch(`/api/attack/${attackId}`)).json();
      } catch (e) { return; }

      const v = verdictFor(row);
      verdict.className = "verdict " + v.cls;
      verdict.innerHTML = (v.spin ? '<span class="spinner"></span> ' : "") + v.text;
      mountLiveview(liveview, row);

      if (row.result) {
        renderTrace(trace, row.result);
        status.textContent = `${row.result.steps.length} steps · ${row.result.duration_ms} ms`;
        if (row.result.evidence && row.result.evidence.encoding) {
          evidence.hidden = false;
          evidence.textContent =
            `evidence — canary via ${row.result.evidence.surface} (${row.result.evidence.encoding}): ${row.result.evidence.evidence || ""}`;
        }
        if (row.status === "done" || row.status === "error") return; // terminal
      }
      setTimeout(poll, 1000);
    };
    poll();
  },
};

const ArenaBoard = {
  init() {
    const refresh = async () => {
      let data;
      try { data = await (await fetch("/api/leaderboard")).json(); } catch (e) { return; }
      const body = document.getElementById("lb-body");
      if (data.board.length) {
        body.innerHTML = data.board.map((w, i) =>
          `<tr><td class="rank">${i + 1}</td><td>${esc(w.player)}</td>` +
          `<td><span class="lvl lvl${w.level}">${w.level}</span></td>` +
          `<td class="muted">${esc(w.vector.replace(/_/g, " "))}</td>` +
          `<td><span class="ttype ${esc(w.trigger_type)}">${esc(w.trigger_type)}</span></td>` +
          `<td>${w.steps}</td><td class="score">${w.score}</td></tr>`).join("");
      }
      setTimeout(refresh, 4000);
    };
    setTimeout(refresh, 4000);
  },
};

/* The big screen. Follows whatever attack is currently running; flashes the
   whole screen red the instant a tripwire fires (DEV.md §5/C4). */
const ArenaDemo = {
  init() {
    const demo = document.getElementById("demo");
    const meta = document.getElementById("d-meta");
    const payload = document.getElementById("d-payload");
    const trace = document.getElementById("d-trace");
    const verdict = document.getElementById("d-verdict");
    const liveview = document.getElementById("d-liveview");
    let lastId = null, wonId = null;

    const poll = async () => {
      let row;
      try { row = await (await fetch("/api/latest")).json(); } catch (e) { return setTimeout(poll, 1500); }
      if (row && row.attack_id) {
        if (row.attack_id !== lastId) {
          lastId = row.attack_id;
          liveview.dataset.mounted = "";
          demo.classList.remove("win");
        }
        meta.innerHTML =
          `<span class="lvl lvl${row.level}">Level ${row.level}</span> ` +
          `<span class="chip">${esc(row.vector.replace(/_/g, " "))}</span> ` +
          `<span class="chip">by ${esc(row.player)}</span>`;
        payload.textContent = row.payload || "";
        mountLiveview(liveview, row);
        if (row.result) {
          renderTrace(trace, row.result);
          const v = verdictFor(row);
          verdict.textContent = v.text;
          if (v.cls === "win" && wonId !== row.attack_id) {
            wonId = row.attack_id;
            demo.classList.add("win");
          }
        } else {
          verdict.textContent = row.status === "running" ? "agent is running…" : "queued";
        }
      }
      setTimeout(poll, 1200);
    };
    poll();
  },
};

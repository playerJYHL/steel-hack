"""The browser-only sandbox: a real Steel cloud browser as the box.

This is the isolation the local sandbox cannot give and the shell sandbox needed
a whole cloud machine for. The agent here has no shell — it operates a browser
(read a page, open a URL). The forbidden action is a web exfil: the agent, fooled
by an injection in the page it reads, puts the honeypot secret into a request the
browser makes. Every request the browser issues is intercepted through Playwright
and handed to the same EgressMonitor the local path uses, so the multi-encoding
canary detector and the scoring are reused unchanged. A caught request is aborted
— the secret never actually leaves — and the attempt is the win.

Nothing runs on our infrastructure: the browser is Steel's, the secret is a
honeypot held only in the agent's prompt, and the session is released in a
finally. `viewer_url` is the live view for the big screen.
"""

from __future__ import annotations

import os
import traceback
from typing import Any

from tripwire.inspect import EgressMonitor, RequestFacts

from .sandbox import Sandbox, SeededScenario, ToolResult


class SteelBrowserSandbox(Sandbox):
    name = "steel"

    def __init__(self, scenario: SeededScenario, monitor: EgressMonitor, *, api_key: str | None = None) -> None:
        from playwright.sync_api import sync_playwright
        from steel import Steel

        self.scenario: SeededScenario = scenario
        self.monitor: EgressMonitor = monitor
        self._key: str = api_key or os.environ["STEEL_API_KEY"]
        self._client: Any = Steel(steel_api_key=self._key)
        self._session: Any = self._client.sessions.create()
        self.session_id = self._session.id
        self.viewer_url = self._live_url(self._session)
        self._released: bool = False

        self._pw: Any = sync_playwright().start()
        self._browser: Any = self._pw.chromium.connect_over_cdp(
            f"wss://connect.steel.dev?apiKey={self._key}&sessionId={self._session.id}"
        )
        context = self._browser.contexts[0]
        self._page: Any = context.pages[0] if context.pages else context.new_page()
        context.route("**/*", self._on_route)
        # The bait page is loaded straight into the cloud browser — no hosting.
        self._page.set_content(self.scenario.page_html, wait_until="domcontentloaded")

    @staticmethod
    def _live_url(session: Any) -> str | None:
        dbg = getattr(session, "debug_url", None)
        if dbg:
            return dbg + ("&interactive=false" if "?" in dbg else "?interactive=false")
        return getattr(session, "session_viewer_url", None)

    def _on_route(self, route: Any) -> None:
        req = route.request
        try:
            headers = req.all_headers()
        except Exception:
            headers = {}
        facts = RequestFacts.from_url(req.method, req.url, headers=headers, body=(req.post_data or ""))
        verdict = self.monitor.inspect(facts)
        try:
            if verdict.allow:
                route.continue_()
            else:
                route.abort()
        except Exception:
            pass

    def read_page(self, url: str) -> ToolResult:
        try:
            return ToolResult(self._page.inner_text("body")[:6000])
        except Exception as exc:
            return ToolResult(f"read error: {exc}", is_error=True)

    def http(self, url: str, method: str = "GET", body: str = "") -> ToolResult:
        # The exfil channel. Both a navigation and a fetch go through the same
        # request interceptor, so the canary is caught either way.
        try:
            if body or method.upper() != "GET":
                self._page.evaluate(
                    "([u,m,b]) => { try { fetch(u,{method:m, body:b||undefined, mode:'no-cors'}); } catch(e){} }",
                    [url, method, body],
                )
                self._page.wait_for_timeout(400)
            else:
                try:
                    self._page.goto(url, wait_until="domcontentloaded", timeout=12000)
                except Exception:
                    pass
            return ToolResult('{"status": "ok"}')
        except Exception as exc:
            return ToolResult(f"request error: {exc}", is_error=True)

    def bash(self, cmd: str) -> ToolResult:
        return ToolResult(
            "shell is not available: this agent operates a browser only, it has no terminal",
            is_error=True,
        )

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            self._browser.close()
        except Exception:
            pass
        try:
            self._pw.stop()
        except Exception:
            pass
        try:
            self._client.sessions.release(self._session.id)
        except Exception:
            traceback.print_exc()

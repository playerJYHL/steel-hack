"""The cloud browser the agent reads pages through — the Steel Browser half of
the hybrid build (PROJECT_CONTEXT §3).

The agent's bash/http run inside a Steel Computer; its `read_page` runs here, in a
separate Steel Browser session (cloud Chrome), reached over CDP with Playwright —
the working reference in DEV.md §0. Two reasons it's a real browser and not just
"return the HTML we generated":

  * The injection reaches the agent the way it would in the wild — through a real
    render. The page_hidden_text vector hides the payload off-screen and
    white-on-white, which a human watching the live view never sees but the
    browser's innerText still returns. That gap IS the demo.
  * The Steel live view of this session is what puts "the agent is being fooled
    right now" on the big screen (DEV.md §5/C4).

The page is handed to the browser as a data: URL, so nothing needs hosting and
the booth's reachability never matters.

Two implementations behind one interface, mirroring the Computer backends:
  * SteelBrowser — real cloud Chrome over CDP.
  * LocalBrowser — a stand-in that extracts text from the HTML with no browser,
    so the hybrid orchestration is testable with no key and no network.
"""

from __future__ import annotations

import base64
import os
import re
from typing import Optional


class BrowserClient:
    """Interface: render our page (or open a URL) and return the text an agent
    would ingest."""

    viewer_url: Optional[str] = None
    session_id: Optional[str] = None

    def render_html(self, html: str) -> str:
        raise NotImplementedError

    def open_url(self, url: str) -> str:
        raise NotImplementedError

    def release(self) -> None:
        raise NotImplementedError


# The text extractor. innerText (not textContent) on purpose: it returns
# off-screen and zero-size text — where page_hidden_text hides the payload — but
# omits display:none, which is the realistic middle ground for how a browsing
# agent "reads" a page, and keeps the live view looking like an ordinary article.
_EXTRACT_JS = "() => document.body ? document.body.innerText : document.documentElement.innerText"


class SteelBrowser(BrowserClient):
    def __init__(self, *, api_key: str | None = None, connect_timeout_ms: int = 30000):
        from steel import Steel  # lazy — only the live path needs the SDK

        self._key = api_key or os.environ["STEEL_API_KEY"]
        self._connect_timeout = connect_timeout_ms
        self._client = Steel(steel_api_key=self._key)
        self._session = self._client.sessions.create()
        self.session_id = self._session.id
        self.viewer_url = getattr(self._session, "session_viewer_url", None)
        self._ws = self._session.websocket_url
        self._pw = None
        self._browser = None
        self._page = None

    # -- CDP connection (lazy, reconnecting) ---------------------------------

    def _connect(self):
        if self._page is not None:
            return self._page
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        # Steel wants the api key on the CDP url.
        self._browser = self._pw.chromium.connect_over_cdp(
            f"{self._ws}&apiKey={self._key}", timeout=self._connect_timeout)
        ctx = self._browser.contexts[0] if self._browser.contexts else self._browser.new_context()
        self._page = ctx.pages[0] if ctx.pages else ctx.new_page()
        return self._page

    def _reconnect(self):
        self._teardown_cdp()
        return self._connect()

    def _goto_and_extract(self, url: str) -> str:
        for attempt in (1, 2):
            try:
                page = self._connect()
                page.goto(url, wait_until="domcontentloaded", timeout=self._connect_timeout)
                # let injected/off-screen nodes settle
                try:
                    page.wait_for_timeout(300)
                except Exception:
                    pass
                return page.evaluate(_EXTRACT_JS) or ""
            except Exception:
                if attempt == 1:
                    self._reconnect()
                    continue
                raise

    def render_html(self, html: str) -> str:
        b64 = base64.b64encode(html.encode("utf-8")).decode("ascii")
        return self._goto_and_extract(f"data:text/html;base64,{b64}")

    def open_url(self, url: str) -> str:
        return self._goto_and_extract(url)

    # -- teardown ------------------------------------------------------------

    def _teardown_cdp(self) -> None:
        for closer in (getattr(self._browser, "close", None),
                       getattr(self._pw, "stop", None)):
            try:
                if closer:
                    closer()
            except Exception:
                pass
        self._pw = self._browser = self._page = None

    def release(self) -> None:
        self._teardown_cdp()
        try:
            if self._session is not None:
                self._client.sessions.release(self._session.id)
                self._session = None
        except Exception:
            import traceback
            traceback.print_exc()


class LocalBrowser(BrowserClient):
    """No-browser stand-in: extracts text from HTML so the hybrid orchestration
    is testable offline. Returns ALL text (including hidden), which is a superset
    of what a real innerText returns — enough to prove the injection reaches the
    agent."""

    _TAG = re.compile(r"<[^>]+>")
    _COMMENT = re.compile(r"<!--(.*?)-->", re.S)

    def __init__(self):
        self.viewer_url = None
        self.session_id = "local-browser"

    def render_html(self, html: str) -> str:
        # keep comment text (a real DOM wouldn't, but off-screen/white-on-white
        # copies of the same payload are what matter and those survive too)
        text = self._COMMENT.sub(lambda m: " " + m.group(1) + " ", html)
        text = self._TAG.sub(" ", text)
        import html as _h
        text = _h.unescape(text)
        return re.sub(r"[ \t]+", " ", text).strip()

    def open_url(self, url: str) -> str:
        return f"(local-browser stand-in did not fetch {url})"

    def release(self) -> None:
        pass

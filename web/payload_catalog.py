"""Serve the starter payload library to the front-end as JSON.

Small enough to be its own module so app.py stays about routing. The catalog
feeds the "start from an example" menu on the submission form (DEV.md §B3).
"""

from __future__ import annotations

from flask import Flask, jsonify

from channels.payloads import load_payloads


def register_catalog(app: Flask) -> None:
    @app.get("/api/payloads")
    def api_payloads():
        # Never leak the verified/answer status into the room as a solutions key,
        # but the starting text and its target level/vector are the point.
        return jsonify([
            {"id": p["id"], "title": p["title"], "level": p["level"],
             "vector": p["vector"], "text": p["text"]}
            for p in load_payloads()
        ])

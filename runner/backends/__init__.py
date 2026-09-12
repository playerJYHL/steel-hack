"""Pluggable backends: which model drives the agent, which sandbox it runs in.

Two axes, chosen independently:
  * model  — `anthropic` (a real Claude) or `scripted` (a deterministic double)
  * sandbox — `steel` (a real Steel Computer) or `local` (a temp dir here)

The scripted model and the local sandbox exist so the entire arena — tripwire,
runner, web UI, leaderboard — is testable with no API keys and no spend, which
is the cost discipline of PROJECT_CONTEXT §9 built into the architecture rather
than bolted on. Every result records which backends actually ran, so a free
local dry-run can never be mistaken for a real one.
"""

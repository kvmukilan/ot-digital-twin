"""Shared fixtures for the OT Digital Twin test suite.

Every test runs fully OFFLINE: there is no network access and no LLM/OpenAI
key. The autouse ``_no_llm`` fixture scrubs provider credentials from both the
environment and the already-imported ``scenario_generator`` module so a real
API call can never happen, even on a developer machine that has keys set.
"""

from __future__ import annotations

import socket

import pytest

from ot_twin.environment.historian import Historian


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch):
    """Guarantee the LLM layer stays offline for every test.

    ``config.py`` reads the keys into module globals at import time and
    ``scenario_generator`` binds them into its own namespace, so we blank them
    there directly rather than relying on ``os.environ``.
    """
    import ot_twin.llm_generator.scenario_generator as sg

    for name in ("OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"):
        monkeypatch.setattr(sg, name, "", raising=False)
    for var in (
        "OPENAI_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def historian(tmp_path):
    """A Historian backed by a throwaway SQLite file (auto-cleaned)."""
    return Historian(db_path=str(tmp_path / "test_historian.db"))


def _free_port() -> int:
    """Return an unused localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
async def plc():
    """Start an in-process PLC slave on a random localhost port.

    Yields ``(host, port)`` and always stops the server afterwards, so no
    listener is left running between tests.
    """
    from ot_twin.environment.plc_slave import PLCSlave

    port = _free_port()
    slave = PLCSlave(host="127.0.0.1", port=port)
    await slave.start_background()
    try:
        yield "127.0.0.1", port
    finally:
        await slave.stop()

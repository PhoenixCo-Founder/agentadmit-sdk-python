"""Regression tests for 429 retry handling in _introspect_with_retry.

A server-supplied Retry-After header is untrusted input: a compromised or
misconfigured endpoint could send `Retry-After: 3600` and pin the caller's
request thread for an hour. Every wait must be capped at 30 seconds, and
cumulative wait across retries of one verify call must be capped at 120
seconds.
"""

from types import SimpleNamespace

import pytest

from agentadmit import auth as auth_mod
from agentadmit.exceptions import RateLimitError


def _resp(status_code, headers=None):
    return SimpleNamespace(status_code=status_code, headers=headers or {})


@pytest.fixture()
def recorded_sleeps(monkeypatch):
    """Record sleeps instead of actually sleeping; make jitter deterministic."""
    sleeps = []
    monkeypatch.setattr(auth_mod.time, "sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(auth_mod.random, "uniform", lambda a, b: 0.25)
    return sleeps


def _patch_post(monkeypatch, responses):
    """httpx.post returns each response in order; repeats the last one."""
    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(url)
        idx = min(len(calls) - 1, len(responses) - 1)
        return responses[idx]

    monkeypatch.setattr(auth_mod.httpx, "post", fake_post)
    return calls


def test_huge_retry_after_is_capped_at_30s(monkeypatch, recorded_sleeps):
    _patch_post(monkeypatch, [_resp(429, {"Retry-After": "3600"})])

    with pytest.raises(RateLimitError) as exc_info:
        auth_mod._introspect_with_retry(
            "https://agentadmit.example/api/v1/verify",
            "ag_at_x", "app_test", "aa_key", max_retries=3,
        )

    assert "Max retries" in str(exc_info.value)
    assert len(recorded_sleeps) == 3
    for slept in recorded_sleeps:
        assert slept <= 30.5  # 30s cap + max jitter — never the requested 3600s


def test_cumulative_budget_exhausted(monkeypatch, recorded_sleeps):
    # High max_retries so the 120s budget, not the retry count, is the limiter.
    _patch_post(monkeypatch, [_resp(429, {"Retry-After": "30"})])

    with pytest.raises(RateLimitError) as exc_info:
        auth_mod._introspect_with_retry(
            "https://agentadmit.example/api/v1/verify",
            "ag_at_x", "app_test", "aa_key", max_retries=99,
        )

    assert "budget" in str(exc_info.value)
    # 30.25s per wait -> 3 sleeps (90.75s); the 4th would exceed 120s.
    assert len(recorded_sleeps) == 3


def test_recovers_when_server_stops_rate_limiting(monkeypatch, recorded_sleeps):
    calls = _patch_post(monkeypatch, [
        _resp(429, {"Retry-After": "2"}),
        _resp(200),
    ])

    response = auth_mod._introspect_with_retry(
        "https://agentadmit.example/api/v1/verify",
        "ag_at_x", "app_test", "aa_key", max_retries=3,
    )

    assert response.status_code == 200
    assert len(calls) == 2
    assert recorded_sleeps == [2.25]


def test_negative_retry_after_clamped_to_zero(monkeypatch, recorded_sleeps):
    _patch_post(monkeypatch, [
        _resp(429, {"Retry-After": "-500"}),
        _resp(200),
    ])

    response = auth_mod._introspect_with_retry(
        "https://agentadmit.example/api/v1/verify",
        "ag_at_x", "app_test", "aa_key", max_retries=3,
    )

    assert response.status_code == 200
    assert recorded_sleeps == [0.25]  # clamped to 0 + jitter only

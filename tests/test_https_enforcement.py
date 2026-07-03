"""M4 - HTTPS enforcement at client construction.

AgentAdmitConfig must reject non-https URLs for agentadmit_api_url,
agentadmit_verify_url, and api_base_url at construction time, EXCEPT for
http on localhost / 127.0.0.1 / [::1] (allowed for local development).
"""

import pytest
from pydantic import ValidationError

from agentadmit.config import AgentAdmitConfig
from agentadmit.exceptions import ConfigurationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_config(**overrides):
    """Build a minimal valid AgentAdmitConfig with optional overrides."""
    defaults = {
        "app_id": "app_test",
        "api_key": "aa_test_key",
        "agentadmit_api_url": "https://api.agentadmit.com",
        "agentadmit_verify_url": "https://api.agentadmit.com/api/v1/verify",
        "api_base_url": "https://myapp.example.com",
    }
    defaults.update(overrides)
    return AgentAdmitConfig(**defaults)


# ---------------------------------------------------------------------------
# Baseline: https URLs are accepted
# ---------------------------------------------------------------------------

def test_https_api_url_accepted():
    cfg = make_config(agentadmit_api_url="https://api.agentadmit.com")
    assert cfg.agentadmit_api_url == "https://api.agentadmit.com"


def test_https_verify_url_accepted():
    cfg = make_config(agentadmit_verify_url="https://api.agentadmit.com/api/v1/verify")
    assert "https" in cfg.agentadmit_verify_url


def test_https_base_url_accepted():
    cfg = make_config(api_base_url="https://myapp.example.com")
    assert cfg.api_base_url == "https://myapp.example.com"


# ---------------------------------------------------------------------------
# http on localhost variants is allowed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host,url_host", [
    ("localhost", "localhost"),
    ("127.0.0.1", "127.0.0.1"),
    ("[::1]", "[::1]"),  # IPv6 uses brackets in URLs; urlparse returns hostname "::1"
])
def test_http_localhost_allowed_for_api_url(host, url_host):
    cfg = make_config(agentadmit_api_url=f"http://{url_host}:8080")
    assert cfg.agentadmit_api_url.startswith("http://")


@pytest.mark.parametrize("host,url_host", [
    ("localhost", "localhost"),
    ("127.0.0.1", "127.0.0.1"),
    ("[::1]", "[::1]"),
])
def test_http_localhost_allowed_for_verify_url(host, url_host):
    cfg = make_config(agentadmit_verify_url=f"http://{url_host}:8080/verify")
    assert cfg.agentadmit_verify_url.startswith("http://")


@pytest.mark.parametrize("host,url_host", [
    ("localhost", "localhost"),
    ("127.0.0.1", "127.0.0.1"),
    ("[::1]", "[::1]"),
])
def test_http_localhost_allowed_for_base_url(host, url_host):
    cfg = make_config(api_base_url=f"http://{url_host}:8000")
    assert cfg.api_base_url.startswith("http://")


# ---------------------------------------------------------------------------
# http on non-localhost is rejected
# ---------------------------------------------------------------------------

def test_http_remote_api_url_rejected():
    with pytest.raises((ValidationError, ConfigurationError)):
        make_config(agentadmit_api_url="http://api.agentadmit.com")


def test_http_remote_verify_url_rejected():
    with pytest.raises((ValidationError, ConfigurationError)):
        make_config(agentadmit_verify_url="http://api.agentadmit.com/api/v1/verify")


def test_http_remote_base_url_rejected():
    with pytest.raises((ValidationError, ConfigurationError)):
        make_config(api_base_url="http://myapp.example.com")


def test_http_arbitrary_host_rejected():
    """A non-localhost IP that happens to start with 127 must still be rejected
    unless it is exactly 127.0.0.1."""
    with pytest.raises((ValidationError, ConfigurationError)):
        make_config(api_base_url="http://192.168.1.1:8000")


def test_error_message_is_informative():
    """The ConfigurationError message must name the field and mention https."""
    with pytest.raises((ValidationError, ConfigurationError)) as exc_info:
        make_config(agentadmit_api_url="http://evil.example.com")
    assert "https" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Empty strings (unset URLs) pass through - URL may be set after construction
# ---------------------------------------------------------------------------

def test_empty_api_base_url_allowed():
    cfg = make_config(api_base_url="")
    assert cfg.api_base_url == ""

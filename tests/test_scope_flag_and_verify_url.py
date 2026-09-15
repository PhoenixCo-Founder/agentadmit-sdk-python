"""Regression tests from the TrainerTracer dogfood rig (Sep 3, 2026).

1. ``ScopeDefinition`` must keep ``confirm_each_time`` — TT builds
   ``config.scopes`` via ``ScopeDefinition(**scope)``, and pydantic silently
   dropped the unknown key, so every scope synced with the flag False.
2. ``agentadmit_verify_url`` must follow a non-default ``agentadmit_api_url``
   when it is not set explicitly — otherwise the catalog syncs to one service
   while every per-call verify goes to production.
"""
from agentadmit.config import AgentAdmitConfig, ScopeDefinition
from agentadmit import middleware as mw


def test_scope_definition_keeps_confirm_each_time():
    s = ScopeDefinition(**{"name": "manage:subscription", "description": "x", "category": "Payments", "role": "user", "confirm_each_time": True})
    assert s.confirm_each_time is True
    assert ScopeDefinition(name="read:profile", description="x").confirm_each_time is False


def test_startup_sync_payload_carries_confirm_each_time(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {"count": 2}

    class _Client:
        def __init__(self, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return None

        def post(self, url, headers, json):
            captured["payload"] = json
            return _Resp()

    monkeypatch.setattr(mw.httpx, "Client", _Client)
    cfg = AgentAdmitConfig(
        app_id="app_x", api_key="aa_test_x",
        scopes=[
            ScopeDefinition(name="read:profile", description="r"),
            ScopeDefinition(name="manage:subscription", description="m", confirm_each_time=True),
        ],
    )
    assert mw._sync_scopes_to_hosted_service(cfg) is True
    by_name = {s["name"]: s for s in captured["payload"]["scopes"]}
    assert by_name["manage:subscription"]["confirm_each_time"] is True
    assert by_name["read:profile"]["confirm_each_time"] is False


def test_verify_url_follows_non_default_api_url():
    cfg = AgentAdmitConfig(agentadmit_api_url="http://127.0.0.1:3003")
    assert cfg.agentadmit_verify_url == "http://127.0.0.1:3003/api/v1/verify"
    cfg2 = AgentAdmitConfig(agentadmit_api_url="https://staging.agentadmit.example/")
    assert cfg2.agentadmit_verify_url == "https://staging.agentadmit.example/api/v1/verify"


def test_default_and_explicit_verify_url_unchanged():
    assert AgentAdmitConfig().agentadmit_verify_url == "https://api.agentadmit.com/api/v1/verify"
    cfg = AgentAdmitConfig(agentadmit_api_url="http://localhost:9000", agentadmit_verify_url="http://localhost:9000/verify")
    assert cfg.agentadmit_verify_url == "http://localhost:9000/verify"


def test_confirm_each_time_round_trips_through_yaml_and_model_dump(tmp_path, monkeypatch):
    """The flag must survive YAML -> ScopeDefinition -> dict (the /scopes
    endpoint and the catalog sync both read model_dump())."""
    from agentadmit import config as cfg_mod

    cfg_path = tmp_path / "agentadmit.yaml"
    cfg_path.write_text(
        "app_id: app_x\n"
        "api_key: aa_test_x\n"
        "scopes:\n"
        "  - name: read:profile\n"
        "    description: r\n"
        "  - name: manage:subscription\n"
        "    description: m\n"
        "    confirm_each_time: true\n"
        "  - read:orders\n"
    )
    monkeypatch.setattr(cfg_mod, "_config", None)
    loaded = cfg_mod.load_config(str(cfg_path))
    by_name = {s.name: s for s in loaded.scopes}
    assert by_name["manage:subscription"].confirm_each_time is True
    assert by_name["read:profile"].confirm_each_time is False
    assert by_name["read:orders"].confirm_each_time is False  # string shorthand
    dumped = {d["name"]: d for d in cfg_mod.get_scope_metadata()}
    assert dumped["manage:subscription"]["confirm_each_time"] is True
    assert ScopeDefinition(**dumped["manage:subscription"]).confirm_each_time is True

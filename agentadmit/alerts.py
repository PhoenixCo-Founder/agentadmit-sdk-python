"""
agentadmit.alerts
-----------------
Alert configuration and event management for the AgentAdmit hosted service.

Usage:
    from agentadmit import configure_alerts, list_alerts, get_alert_config

    # Configure a volume spike alert
    result = configure_alerts(
        app_id="app_abc123",
        alert_type="volume_spike",
        enabled=True,
        threshold_value=100,
        threshold_window_minutes=5,
    )

    # List alert events
    events = list_alerts(app_id="app_abc123", alert_type="volume_spike")

    # Get current alert config
    config = get_alert_config(app_id="app_abc123")
"""

from typing import Optional
from agentadmit.routes import _call_hosted_service


ALERT_TYPES = [
    "volume_spike",
    "failed_scope_attempts",
    "burst_pattern",
    "stale_reactivation",
    "new_scope_usage",
    "revoked_connection_attempt",
]


def configure_alerts(
    app_id: str,
    alert_type: str,
    connection_id: Optional[str] = None,
    enabled: Optional[bool] = None,
    threshold_value: Optional[float] = None,
    threshold_window_minutes: Optional[int] = None,
    threshold_rate_per_minute: Optional[float] = None,
    stale_days: Optional[int] = None,
    kill_switch_enabled: Optional[bool] = None,
    kill_switch_threshold_value: Optional[float] = None,
    kill_switch_threshold_window_minutes: Optional[int] = None,
) -> dict:
    """
    Configure alert thresholds for an app or connection.

    Args:
        app_id: Your AgentAdmit application ID.
        alert_type: One of the 6 alert types: volume_spike, failed_scope_attempts,
            burst_pattern, stale_reactivation, new_scope_usage, revoked_connection_attempt.
        connection_id: Optional — scope the config to a specific connection.
        enabled: Whether this alert type is enabled.
        threshold_value: Alert fires when event count exceeds this value.
        threshold_window_minutes: Time window for threshold evaluation (minutes).
        threshold_rate_per_minute: Alert fires when rate exceeds this value per minute.
        stale_days: Days of inactivity before a stale_reactivation alert fires.
        kill_switch_enabled: If True, automatically revoke the connection when threshold is hit.
        kill_switch_threshold_value: Threshold for automatic kill switch activation.
        kill_switch_threshold_window_minutes: Time window for kill switch threshold (minutes).

    Returns:
        dict: { "ok": True, "config": {...} }

    Raises:
        fastapi.HTTPException: If the hosted service returns an error.
    """
    body: dict = {"app_id": app_id, "alert_type": alert_type}
    if connection_id is not None:
        body["connection_id"] = connection_id
    if enabled is not None:
        body["enabled"] = enabled
    if threshold_value is not None:
        body["threshold_value"] = threshold_value
    if threshold_window_minutes is not None:
        body["threshold_window_minutes"] = threshold_window_minutes
    if threshold_rate_per_minute is not None:
        body["threshold_rate_per_minute"] = threshold_rate_per_minute
    if stale_days is not None:
        body["stale_days"] = stale_days
    if kill_switch_enabled is not None:
        body["kill_switch_enabled"] = kill_switch_enabled
    if kill_switch_threshold_value is not None:
        body["kill_switch_threshold_value"] = kill_switch_threshold_value
    if kill_switch_threshold_window_minutes is not None:
        body["kill_switch_threshold_window_minutes"] = kill_switch_threshold_window_minutes

    resp = _call_hosted_service("POST", "/api/v1/alerts", json=body)
    return resp.json()


def list_alerts(
    app_id: str,
    connection_id: Optional[str] = None,
    alert_type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """
    List alert events for an app.

    Args:
        app_id: Your AgentAdmit application ID.
        connection_id: Optional — filter by connection.
        alert_type: Optional — filter by alert type.
        limit: Maximum number of events to return (default 50).
        offset: Pagination offset (default 0).

    Returns:
        dict: { "events": [...], "total": int, "limit": int, "offset": int }
    """
    params = f"?app_id={app_id}&limit={limit}&offset={offset}"
    if connection_id:
        params += f"&connection_id={connection_id}"
    if alert_type:
        params += f"&alert_type={alert_type}"

    resp = _call_hosted_service("GET", f"/api/v1/alerts{params}")
    return resp.json()


def get_alert_config(
    app_id: str,
    connection_id: Optional[str] = None,
) -> dict:
    """
    Get the current alert configuration for an app.

    Args:
        app_id: Your AgentAdmit application ID.
        connection_id: Optional — get config for a specific connection.

    Returns:
        dict: {
            "app_id": str,
            "app_level": { alert_type: config_dict, ... },
            "connection_overrides": { connection_id: { alert_type: config_dict } },
            "alert_types": [str, ...],
        }
    """
    params = f"?app_id={app_id}"
    if connection_id:
        params += f"&connection_id={connection_id}"

    resp = _call_hosted_service("GET", f"/api/v1/alerts/config{params}")
    return resp.json()

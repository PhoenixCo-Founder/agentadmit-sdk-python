# AgentAdmit SDK for Python

User-mediated AI agent authorization for Python apps. Supports **FastAPI**, **Flask**, and **Django**.

> **Get started:** Sign up at [agentadmit.com](https://agentadmit.com) → Get your test keys → Install the SDK → Build.
> Test keys are available immediately after signup. Live keys become available when you subscribe an app.

## Quick Start

```bash
pip install agentadmit
agentadmit init
```

Edit `agentadmit.yaml` to define your scopes, then add to your FastAPI app:

```python
from fastapi import FastAPI, Depends
from agentadmit import AgentAdmitMiddleware, require_scope_if_agent, get_current_user_or_agent

app = FastAPI()

# One-line setup
app.add_middleware(
    AgentAdmitMiddleware,
    config_path="agentadmit.yaml",
    get_current_user=your_auth_dependency,
    verify_user_token=your_token_verifier,
    users_collection="users",
)

# Add scope enforcement to any route
@app.get("/api/orders")
async def get_orders(
    auth_ctx=Depends(get_current_user_or_agent),
    _scope=Depends(require_scope_if_agent("read:orders")),
):
    user = auth_ctx["user"]
    # Your existing logic — unchanged
    return {"orders": get_orders_for_user(user["user_id"])}
```

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Revocation
- Audit logging
- Discovery endpoint

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## CLI

```bash
agentadmit init      # Generate config and keys
agentadmit keys      # Regenerate RS256 key pair
agentadmit check     # Validate configuration
```

## Flask Integration

```python
from flask import Flask
from agentadmit.integrations.flask_integration import AgentAdmitFlask

app = Flask(__name__)
aa = AgentAdmitFlask(app, config_path="agentadmit.yaml")

@app.route('/api/orders')
@aa.require_scope_if_agent('read:orders')
def get_orders():
    return get_user_orders()
```

## Django Integration

```python
# settings.py
AGENTADMIT = {
    'APP_ID': 'app_yourappid',
    'API_KEY': 'aa_test_yourkey',
    'VERIFY_URL': 'https://api.agentadmit.com/api/v1/verify',
}

# views.py
from agentadmit.integrations.django_integration import require_scope_if_agent

@require_scope_if_agent('read:orders')
def get_orders(request):
    return get_user_orders(request)
```

## MCP Server Integration

Building an MCP server in Python? AgentAdmit is the auth layer. MCP servers are app owners. Same SDK, same pricing.

For **STDIO transport** (most MCP servers), the agent includes the token in tool arguments:

```python
import requests
import os

AGENTADMIT_VERIFY_URL = "https://api.agentadmit.com/api/v1/verify"
AGENTADMIT_API_KEY = os.environ["AGENTADMIT_API_KEY"]

def handle_tool_call(name: str, arguments: dict) -> dict:
    # 1. Extract token from tool arguments
    token = arguments.pop("agentadmit_token", None)
    if not token:
        raise PermissionError("agentadmit_token required")
    
    # 2. Validate via AgentAdmit hosted service
    resp = requests.post(
        AGENTADMIT_VERIFY_URL,
        headers={
            "Authorization": f"Bearer {AGENTADMIT_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"token": token},
        timeout=5,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"AgentAdmit verification failed: {resp.status_code}")
    ctx = resp.json()
    # Invalid / expired / revoked tokens return HTTP 200 with active: false
    if not ctx.get("active"):
        raise PermissionError("Invalid or expired token")
    
    # 3. Check scope for this tool
    required_scope = SCOPE_MAP.get(name)
    if required_scope and required_scope not in ctx.get("scopes", []):
        raise PermissionError(f"Missing scope '{required_scope}'")
    
    # 4. Run the tool
    return TOOL_HANDLERS[name](arguments, ctx)
```

For **HTTP transport** (FastAPI-based MCP servers), use the full SDK middleware. The agent sends the token via `Authorization: Bearer` header, same as any HTTP API.

Full MCP integration guide with complete before/after examples: `agentadmit.com/docs/mcp-guide`

**MCP operators:** You also get the embeddable admin panel with revoke capability, admin scopes for your own AI agent to monitor your server, and full audit trail for billing. See the Admin Revocation and Embeddable Admin Panel sections below.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Admin revocation.** As the app operator, you can revoke any user's agent connection via `DELETE /agentadmit/admin/connections/{connection_id}` (requires admin role or `manage:connections` scope). Your own AI agent can also revoke connections if given this scope.

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Python SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter — no changes needed in your app code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header — if present, it overrides the computed backoff delay.

### Configuring max retries

In `agentadmit.yaml`:

```yaml
max_retries: 5  # default: 3. Set to 0 to disable retries.
```

### Handling exhausted retries

When all retries are exhausted, the SDK raises `RateLimitError`:

```python
from agentadmit.exceptions import RateLimitError

try:
    # Any endpoint protected with require_scope / get_agentadmit_user
    ...
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
    print(f"Limit: {e.limit}, Remaining: {e.remaining}, Reset: {e.reset}")
    # Return 429 to the caller or queue for retry
```

`RateLimitError` attributes:
- `retry_after` — seconds from `Retry-After` header (or `None`)
- `limit` — `X-RateLimit-Limit` header value (or `None`)
- `remaining` — `X-RateLimit-Remaining` header value (or `None`)
- `reset` — `X-RateLimit-Reset` Unix timestamp (or `None`)

## Route Registration Order (FastAPI)

When using `create_agentadmit_router()`, the SDK registers default endpoints for
`/agentadmit/scopes`, `/agentadmit/connections/generate-token`, etc.

If you need to **override** any SDK endpoint with your own (e.g., a user-aware
`/scopes` endpoint), register your route **before** calling `app.include_router()`.
FastAPI resolves routes in registration order — the first matching route wins.

```python
# ✅ CORRECT — custom /scopes registered before SDK router
@app.get("/agentadmit/scopes")
async def my_scopes(current_user: dict = Depends(get_current_user)):
    # your user-aware logic
    ...

wellknown_router, agentadmit_router = create_agentadmit_router(...)
app.include_router(wellknown_router)
app.include_router(agentadmit_router, prefix="/agentadmit")

# ❌ WRONG — custom route registered AFTER SDK router (shadowed, never reached)
wellknown_router, agentadmit_router = create_agentadmit_router(...)
app.include_router(agentadmit_router, prefix="/agentadmit")  # SDK route wins
@app.get("/agentadmit/scopes")  # never reached
async def my_scopes(): ...
```

**Tip:** Use the `filter_scopes_for_user` callback parameter on
`create_agentadmit_router()` as a cleaner alternative to overriding `/scopes`
entirely — the SDK handles the endpoint and calls your function to filter results.

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Python SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens by calling AgentAdmit's hosted introspection endpoint (`https://api.agentadmit.com/api/v1/verify`) on every agent request — this is mandatory introspection; there is no local or offline validation mode
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke, audit) using your configured storage backend

### What the SDK does NOT do
- Does not transmit raw end-user PII (such as name, email, or device identifiers) — each introspection request sends the opaque access token and your API key
- Does not perform passive background telemetry or analytics — network calls occur only during active token validation
- Does not maintain its own persistent storage — local state (connections, audit log) lives in the storage backend you configure

### What the AgentAdmit hosted service records
On every token validation, AgentAdmit's `/api/v1/verify` endpoint receives the access token and API key, resolves the token to its `user_id`, `connection_id`, granted `scopes`, and `agent_label`, and records per-call metadata (including the endpoint and timestamp) for billing, audit logging, the security alerts engine, and usage metering. This is integral to how AgentAdmit works and applies to both test and live keys. See the "Mandatory introspection" notes above and the [compliance guide](https://agentadmit.com/docs/compliance) for the full data-handling description.

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.

## Security Alerts

Monitor suspicious agent activity with the AgentAdmit alerts API. Six alert types are supported:
- `volume_spike` — unusual request volume
- `failed_scope_attempts` — repeated scope access failures
- `burst_pattern` — rapid burst of requests
- `stale_reactivation` — dormant connection suddenly active
- `new_scope_usage` — agent using a scope for the first time
- `revoked_connection_attempt` — revoked connection trying to authenticate

### Configure Alert Thresholds

```python
from agentadmit import configure_alerts

result = configure_alerts(
    app_id="app_abc123",
    alert_type="volume_spike",
    enabled=True,
    threshold_value=100,
    threshold_window_minutes=5,
    kill_switch_enabled=True,
    kill_switch_threshold_value=500,
    kill_switch_threshold_window_minutes=10,
)
# {"ok": True, "config": {...}}
```

### List Alert Events

```python
from agentadmit import list_alerts

events = list_alerts(app_id="app_abc123", alert_type="volume_spike", limit=50)
# {"events": [...], "total": 12, "limit": 50, "offset": 0}
```

### Get Current Config

```python
from agentadmit import get_alert_config

config = get_alert_config(app_id="app_abc123")
conn_config = get_alert_config(app_id="app_abc123", connection_id="conn_xyz")
```


### Notifying Your Users

AgentAdmit detects anomalies, fires alerts, and (with kill switch) auto-revokes connections. **How you notify your own users is up to you.** AgentAdmit provides the data — you deliver it through your own system (in-app notifications, email, push, etc.).

- **Poll alerts** — Use the SDK methods above from your backend to check for new events, then notify users through your existing system.
- **Webhook delivery** — Configure a webhook URL in your AgentAdmit dashboard. When an alert fires, AgentAdmit POSTs the payload to your server, signed with your `whsec_…` secret. Always verify the signature before trusting the payload:

  ```python
  from agentadmit import verify_webhook_signature, WebhookSignatureError

  @app.post("/agentadmit/alerts")
  async def alerts(request: Request):
      payload = await request.body()
      try:
          verify_webhook_signature(
              payload,
              request.headers.get("X-AgentAdmit-Signature", ""),
              secret=os.environ["AGENTADMIT_WEBHOOK_SECRET"],  # whsec_…
          )
      except WebhookSignatureError:
          return JSONResponse({"error": "invalid_signature"}, status_code=400)
      event = json.loads(payload)
      ...
  ```

  The header format is `t=<unix_ts>,v1=<hex>` — an HMAC-SHA256 of `{t}.{raw_body}` keyed with your signing secret. The helper compares in constant time and rejects timestamps more than 5 minutes off (replay protection).
- **React SDK** — Embed the `<AlertsPanel>` component so users can view their own alert history and tighten thresholds.

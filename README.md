# AgentAdmit SDK for Python

User-mediated AI agent authorization for Python apps. Supports **FastAPI**, **Flask**, and **Django**.

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

1. User clicks "AI Agent Access" in your app
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
from agentadmit.flask import AgentAdmitMiddleware

app = Flask(__name__)
agentadmit = AgentAdmitMiddleware(app)

@app.route('/api/orders')
@agentadmit.require_scope('read:orders')
def get_orders():
    return get_user_orders()
```

## Django Integration

```python
# settings.py
AGENTADMIT = {
    'APP_ID': 'app_yourappid',
    'API_KEY': 'ak_test_yourkey',
    'VERIFY_URL': 'https://api.agentadmit.com/v1/verify',
}

# views.py
from agentadmit.django import require_scope

@require_scope('read:orders')
def get_orders(request):
    return get_user_orders(request)
```

## MCP Server Integration

Building an MCP server in Python? AgentAdmit is the auth layer. MCP servers are app owners. Same SDK, same pricing.

For **STDIO transport** (most MCP servers), the agent includes the token in tool arguments:

```python
import requests
import os

AGENTADMIT_VERIFY_URL = "https://api.agentadmit.com/v1/verify"
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
            "Authorization": f"Bearer {token}",
            "X-Api-Key": AGENTADMIT_API_KEY,
        },
        timeout=5,
    )
    if resp.status_code != 200:
        raise PermissionError("Invalid or expired token")
    ctx = resp.json()
    
    # 3. Check scope for this tool
    required_scope = SCOPE_MAP.get(name)
    if required_scope and required_scope not in ctx.get("scopes", []):
        raise PermissionError(f"Missing scope '{required_scope}'")
    
    # 4. Run the tool
    return TOOL_HANDLERS[name](arguments, ctx)
```

For **HTTP transport** (FastAPI-based MCP servers), use the full SDK middleware. The agent sends the token via `Authorization: Bearer` header, same as any HTTP API.

Full MCP integration guide with complete before/after examples: `docs.agentadmit.com/mcp`

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

## Documentation

Full integration guide: https://docs.agentadmit.com/getting-started

## License

All rights reserved. Patent pending.

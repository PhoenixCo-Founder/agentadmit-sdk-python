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

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Documentation

Full integration guide: https://docs.agentadmit.com/getting-started

## License

All rights reserved. Patent pending.

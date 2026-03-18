# AgentAdmit SDK for Python

User-mediated AI agent authorization. Plug-and-play for any FastAPI app.

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

## Documentation

https://docs.agentadmit.app/sdk

## License

All rights reserved. Patent pending.

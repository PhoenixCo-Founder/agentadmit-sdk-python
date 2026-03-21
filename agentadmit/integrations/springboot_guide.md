# AgentAdmit — Spring Boot Integration Guide

_Java/Spring Boot integration for AgentAdmit._

## Installation

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>app.agentadmit</groupId>
    <artifactId>agentadmit-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

Or `build.gradle`:

```groovy
implementation 'app.agentadmit:agentadmit-spring-boot-starter:0.1.0'
```

## Configuration

`application.yml`:

```yaml
agentadmit:
  app-id: "app_abc123"
  api-key: "aa_live_xxxxxxxxxx"
  verify-url: "https://api.agentadmit.com/v1/verify"
  api-url: "https://api.agentadmit.com"
  user-lookup-field: "userId"
```

## Usage

```java
import app.agentadmit.AgentAdmitAuth;
import app.agentadmit.RequireScope;
import app.agentadmit.AgentContext;

@RestController
@RequestMapping("/api")
public class OrderController {

    // Scope enforcement — agent must have this scope
    @GetMapping("/orders")
    @RequireScope("read:orders")
    public List<Order> getOrders(@AgentContext AuthContext auth) {
        String userId = auth.getUserId();
        return orderService.getOrdersForUser(userId);
    }

    // Dual-token — works for both regular users and agents
    @GetMapping("/profile")
    @RequireScopeIfAgent("read:profile")
    public UserProfile getProfile(@AgentContext AuthContext auth) {
        return profileService.getProfile(auth.getUserId());
    }
}
```

## How It Works

The Spring Boot starter auto-configures:

1. **`AgentAdmitFilter`** — Servlet filter that intercepts requests with `ag_at_` tokens
2. **`@RequireScope`** — Annotation that enforces scope on a controller method
3. **`@RequireScopeIfAgent`** — Annotation that enforces scope only for agent tokens, passes through for regular users
4. **`@AgentContext`** — Parameter annotation that injects the authenticated user/agent context
5. **Introspection client** — HTTP client that validates tokens via `api.agentadmit.com/v1/verify`
6. **Audit logging** — Automatic logging of every scoped access

All token validation goes through AgentAdmit's hosted introspection endpoint. No local JWT validation.

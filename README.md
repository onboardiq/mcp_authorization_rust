# mcp-authorization

Per-request schema-level authorization for MCP tool servers in Rust. Type definitions ARE authorization policies — and in Rust, authorization can be a **compile-time guarantee**.

## The Problem

MCP servers expose tools to LLM clients via `tools/list`. Today, every user sees the same tool schemas. If a user lacks permission to use a feature, the best you can do is reject the call with an error *after* the LLM already knows the capability exists and tried to use it.

**Schema-level authorization** solves this by shaping the JSON Schema each user sees *before* they can act on it. Different users hitting the same endpoint receive different tool lists, different input fields, and different output variants — based on their permissions. An LLM cannot hallucinate options it was never shown.

In Ruby and TypeScript, `can?(:flag)` / `ctx.can(flag)` is a runtime policy check that could be forgotten. In Rust, `Proof<C>` is a zero-sized token that can only be obtained by verifying a capability — **the compiler refuses to build code that skips the check**.

## Three Layers of Authorization

| Layer | What it gates | Mechanism |
|-------|--------------|-----------|
| **Tool visibility** | Entire tools | `.authorize("tool_name", "capability")` on the server builder |
| **Input field visibility** | Individual input fields | `#[requires("capability")]` on struct fields |
| **Output variant visibility** | Union branches in output | `#[requires("capability")]` on enum variants |

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
mcp-authorization = { git = "https://github.com/onboardiq/mcp_authorization_rust" }
rmcp = { version = "1.4", features = ["server", "transport-io"] }
schemars = "1"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
```

Define capabilities as zero-sized types, then annotate your schemas:

```rust
use mcp_authorization::{Capability, Proof, AuthContext, AuthSchema, AuthorizedServer};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// Capabilities are zero-sized types
struct ManageWorkflows;
impl Capability for ManageWorkflows {
    const NAME: &'static str = "manage_workflows";
}

struct BackwardRouting;
impl Capability for BackwardRouting {
    const NAME: &'static str = "backward_routing";
}

// Input schema — fields gated by #[requires]
#[derive(Deserialize, JsonSchema, AuthSchema)]
struct AdvanceStepInput {
    pub applicant_id: String,
    pub workflow_id: String,
    #[requires("backward_routing")]
    pub stage_id: Option<String>,       // managers only
    #[requires("backward_routing")]
    pub reason: Option<String>,         // managers only
}

// Output schema — variants gated by #[requires]
#[derive(Serialize, JsonSchema, AuthSchema)]
#[serde(tag = "type")]
enum AdvanceStepOutput {
    Success { applicant_id: String, current_stage: String },
    #[requires("backward_routing")]
    ReroutedSuccess { applicant_id: String, previous_stage: String, current_stage: String },
    Error { code: String, message: String },
}
```

The type-state guarantee — `Proof<C>` in function signatures:

```rust
impl WorkflowServer {
    // This function CANNOT be called without proving BackwardRouting.
    // The compiler enforces it. You cannot forget the auth check.
    fn reroute(
        &self,
        _proof: Proof<BackwardRouting>,  // zero-sized, compiles away
        input: &AdvanceStepInput,
    ) -> AdvanceStepOutput {
        // Can only reach here if BackwardRouting was proven
        AdvanceStepOutput::ReroutedSuccess { /* ... */ }
    }
}
```

At runtime, the proof is obtained from `AuthContext`:

```rust
let auth = AuthContext::new(vec!["manage_workflows", "backward_routing"]);

// Type-state in action
if let Some(proof) = auth.check::<BackwardRouting>() {
    server.reroute(proof, &input)   // compiles — proof obtained
} else {
    server.advance_forward(&input)  // no proof needed
}

// This would not compile:
// server.reroute(???, &input)  // error[E0061]: missing argument of type Proof<BackwardRouting>
```

Wire it up with `AuthorizedServer`, then choose an auth source:

```rust
let server = AuthorizedServer::new(WorkflowServer)
    .register::<AdvanceStepInput, AdvanceStepOutput>(
        "advance_step",
        "Advance an applicant in their workflow",
    )
    .authorize("advance_step", "manage_workflows")
    // Choose where each request's AuthContext comes from. This is also what
    // makes the server a `ServerHandler` — see "Serving" below.
    .deny_by_default();
```

**Operator** calls `tools/list` and sees:

```json
{
  "name": "advance_step",
  "inputSchema": {
    "type": "object",
    "properties": {
      "applicant_id": { "type": "string" },
      "workflow_id": { "type": "string" }
    }
  }
}
```

**Manager** calls `tools/list` and sees:

```json
{
  "name": "advance_step",
  "inputSchema": {
    "type": "object",
    "properties": {
      "applicant_id": { "type": "string" },
      "workflow_id": { "type": "string" },
      "stage_id": { "type": "string" },
      "reason": { "type": "string" }
    }
  }
}
```

The operator's LLM never knows `stage_id` or `reason` exist.

## API Reference

### `Capability` trait

Implement on zero-sized types to define permissions:

```rust
struct Admin;
impl Capability for Admin {
    const NAME: &'static str = "admin";
}
```

### `Proof<C>`

Zero-sized compile-time proof that capability `C` was verified. Cannot be constructed directly — only obtained via `AuthContext::check()` or `AuthContext::require()`. Compiles away entirely at runtime (`size_of::<Proof<C>>() == 0`).

### `AuthContext`

Per-request authorization context. Built by middleware from JWT claims, headers, etc. Stored in rmcp's `RequestContext::extensions`.

```rust
let auth = AuthContext::new(vec!["manage_workflows", "admin"]);

auth.check::<Admin>()          // -> Option<Proof<Admin>>
auth.require::<Admin>()        // -> Result<Proof<Admin>, McpError>
auth.has("admin")              // -> bool (for runtime schema shaping)
```

### `#[derive(AuthSchema)]`

Generates `AuthSchemaMetadata` from `#[requires("capability")]` annotations on struct fields or enum variants. Works alongside `#[derive(JsonSchema)]` — does not modify the type.

### `AuthorizedServer<S, A>`

Wraps any rmcp `ServerHandler`. Intercepts `list_tools` to shape schemas per-user and `call_tool` to enforce tool-level gates. Delegates everything else to the inner handler.

```rust
AuthorizedServer::new(inner_handler)
    .register::<InputType, OutputType>("tool_name", "description")
    .authorize("tool_name", "required_capability")
    .deny_by_default()  // or .with_auth(provider)
```

### Serving — auth is a compile-time requirement

`AuthorizedServer` is a type-state builder. `AuthorizedServer::new(..)` starts in the `NoAuth` state and **deliberately does not implement `ServerHandler`**, so you cannot serve it over any transport until you choose how requests get an `AuthContext`. In the same spirit as `Proof<C>`, forgetting auth is a *build error*, not a runtime panic:

```rust
// Does NOT compile — NoAuth is not a ServerHandler:
// AuthorizedServer::new(handler).serve(transport)

AuthorizedServer::new(handler).deny_by_default().serve(transport)        // ✅
AuthorizedServer::new(handler).with_auth(my_provider).serve(transport)   // ✅
```

Two ways to choose an auth source (the `AuthProvider` trait):

- **`.deny_by_default()`** installs `DenyByDefault`: use an `AuthContext` injected into `RequestContext::extensions` by middleware if present, otherwise resolve to `AuthContext::empty()` (no capabilities). An unauthenticated client therefore sees only ungated tools — the least-privileged view — instead of an error. Ideal for stdio / local / dev, and it transparently picks up a middleware-injected context in production.
- **`.with_auth(provider)`** takes any `AuthProvider`, including a closure `Fn(&RequestContext<RoleServer>) -> AuthContext` — wire it to JWT claims, a DB lookup, or a fixed dev identity.

Where the context comes from is a *runtime* concern (the same binary may serve stdio in dev and HTTP in prod), so it's a provider/closure seam rather than a cargo feature — the core crate stays transport- and framework-free.

### `SchemaShaper`

Standalone schema shaping for use outside the server wrapper:

```rust
let shaped = SchemaShaper::shape_input::<MyInput>(&auth_context);
let shaped = SchemaShaper::shape_output::<MyOutput>(&auth_context);
```

## Architecture

This crate extends [rmcp](https://github.com/modelcontextprotocol/rust-sdk) (the official Rust MCP SDK) rather than forking it. The flow:

1. HTTP middleware extracts user identity → `AuthContext`, inserts into rmcp's `RequestContext::extensions`
2. `AuthorizedServer.list_tools()` reads `AuthContext` from extensions, calls `AuthToolRegistry.materialize(auth)` which filters tools by tool-level gates and shapes input/output schemas by removing fields/variants the user lacks capabilities for
3. `AuthorizedServer.call_tool()` checks tool-level authorization, then delegates to the inner `ServerHandler`
4. Inside tool handlers, `Extension<AuthContext>` extractor provides the auth context. `auth.check::<C>()` returns `Proof<C>` which handler functions can require in their signatures

Schema generation uses `schemars` (compile-time, cached). Per-request work is only the `#[requires]` filtering — hash lookups against the user's capability set.

## Ruby ↔ Rust Mapping

This crate is the Rust counterpart of [mcp_authorization](https://github.com/onboardiq/mcp_authorization) (Ruby gem). The concepts map directly:

| Ruby gem | Rust crate | Enforcement |
|----------|-----------|-------------|
| `authorization :manage_workflows` | `.authorize("tool", "cap")` | Tool hidden from `list_tools` |
| `@requires(:flag)` on param | `#[requires("flag")]` on field | Field removed from JSON Schema |
| `@requires(:flag)` on variant | `#[requires("flag")]` on variant | Variant removed from `oneOf` |
| `can?(:flag)` — runtime, forgettable | `Proof<C>` — compile-time, unforgettable | `error[E0277]` if proof missing |

## Integrating with Existing RBAC

The `AuthContext` interface is deliberately minimal. For systems with complex RBAC (role matrices, action keys, feature flags), construct it from whatever your auth layer provides:

```rust
// Example: from JWT claims
let auth = AuthContext::new(jwt.capabilities.iter().cloned());

// Example: from database lookup
let permissions = db.get_user_permissions(user_id).await?;
let auth = AuthContext::new(permissions);
```

Then insert into rmcp's extensions before the request reaches your handler (via HTTP middleware, transport hooks, etc.).

## Requirements

- Rust 1.75+ (edition 2021)
- rmcp 1.4+

## License

MIT

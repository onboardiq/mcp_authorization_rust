# Changelog

## 0.2.0 (unreleased)

Auth provisioning is now a compile-time requirement, and a missing context no
longer errors — it denies by default.

### Breaking changes

- **`AuthorizedServer` is now a type-state builder: `AuthorizedServer<S, A>`.**
  `AuthorizedServer::new(..)` returns the `NoAuth` state, which **does not
  implement `ServerHandler`**. You must choose an auth source before serving:
  - `.deny_by_default()` — use a middleware-injected `AuthContext` if present,
    else `AuthContext::empty()` (least privilege). Ergonomic for stdio/dev.
  - `.with_auth(provider)` — any `AuthProvider`, including a closure
    `Fn(&RequestContext<RoleServer>) -> AuthContext`.
  Forgetting to choose one is a **compile error**, not a runtime panic.

  Migration: add `.deny_by_default()` (or `.with_auth(..)`) to the end of your
  builder chain before calling `.serve(..)`.

### Changed

- **No more `"missing AuthContext in extensions"` runtime error.** Previously
  `list_tools` returned an internal error when no `AuthContext` was present
  (e.g. over stdio with no middleware), and `call_tool` silently skipped the
  visibility check in the same situation. Now both resolve the context through
  the chosen `AuthProvider`; absence → `AuthContext::empty()` → least-privileged
  view. `call_tool` now **always** enforces tool-level visibility.

### Added

- `AuthProvider` trait + `DenyByDefault` provider (+ blanket impl for closures).
- `AuthContext::empty()` — the deny-by-default identity.
- `NoAuth` / `Authorized<P>` type-state markers and the `ReadyToServe` marker
  trait (with a `#[diagnostic::on_unimplemented]` hint) for use as a bound.
- Doc-tests asserting the compile-time gate: serving without an auth source
  fails to compile; `deny_by_default()` makes it a `ServerHandler`.
- Declared `rust-version = "1.78"` (MSRV) — required by the
  `#[diagnostic::on_unimplemented]` hint on `ReadyToServe`.

### Notes

- The core crate remains transport- and framework-free (just `rmcp`,
  `schemars`, `serde`). An optional HTTP/`tower` middleware helper for extracting
  claims into an `AuthContext` is planned as a separate, opt-in addition.

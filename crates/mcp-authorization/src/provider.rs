//! How a request's [`AuthContext`] is produced.
//!
//! The crate's job is schema shaping *given* an `AuthContext`. **Where** that
//! context comes from — a JWT header, a stdio/dev default, a database lookup —
//! is the integrator's concern, and it's a *runtime* one: the same binary might
//! serve stdio in dev and HTTP in prod. So it's a trait object / closure seam,
//! not a cargo feature.
//!
//! An [`AuthProvider`] never fails: there is no "missing context" error path.
//! Absence of a context resolves to [`AuthContext::empty`] (deny-by-default),
//! which is both safe (least privilege) and ergonomic (stdio just works).

use rmcp::service::{RequestContext, RoleServer};

use crate::capability::AuthContext;

/// Resolves the [`AuthContext`] for a single request.
///
/// Implement this to plug in your auth source. A blanket impl is provided for
/// any `Fn(&RequestContext<RoleServer>) -> AuthContext`, so closures work too:
///
/// ```ignore
/// // stdio / dev: a fixed context
/// let server = AuthorizedServer::new(handler)
///     .with_auth(|_ctx: &_| AuthContext::new(["manage_workflows"]));
/// ```
pub trait AuthProvider: Send + Sync {
    fn auth_for(&self, ctx: &RequestContext<RoleServer>) -> AuthContext;
}

/// The default provider: use an [`AuthContext`] that middleware injected into
/// `RequestContext::extensions` if one is present; otherwise resolve to
/// [`AuthContext::empty`] (deny-by-default).
///
/// This is what [`AuthorizedServer::deny_by_default`](crate::AuthorizedServer::deny_by_default)
/// installs. Over stdio (no middleware) it yields the least-privileged view
/// rather than erroring; behind HTTP middleware that inserts an `AuthContext`,
/// it transparently picks that up.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyByDefault;

impl AuthProvider for DenyByDefault {
    fn auth_for(&self, ctx: &RequestContext<RoleServer>) -> AuthContext {
        ctx.extensions
            .get::<AuthContext>()
            .cloned()
            .unwrap_or_else(AuthContext::empty)
    }
}

impl<F> AuthProvider for F
where
    F: Fn(&RequestContext<RoleServer>) -> AuthContext + Send + Sync,
{
    fn auth_for(&self, ctx: &RequestContext<RoleServer>) -> AuthContext {
        self(ctx)
    }
}

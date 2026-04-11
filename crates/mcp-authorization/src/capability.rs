use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;

/// Marker trait for authorization capabilities.
///
/// Implement this on zero-sized types (ZSTs) to define capabilities:
///
/// ```
/// use mcp_authorization::Capability;
///
/// struct ManageWorkflows;
/// impl Capability for ManageWorkflows {
///     const NAME: &'static str = "manage_workflows";
/// }
/// ```
pub trait Capability: Send + Sync + 'static {
    /// The wire name for this capability (matches JWT claims, DB flags, etc.)
    const NAME: &'static str;
}

/// A zero-sized, compile-time proof that a capability was verified.
///
/// `Proof<C>` cannot be constructed outside this crate — the only way to
/// obtain one is through [`AuthContext::check`] or [`AuthContext::require`].
/// This means any function that demands `Proof<C>` in its signature is
/// *statically guaranteed* to have been preceded by an authorization check.
///
/// ```compile_fail
/// use mcp_authorization::{Capability, Proof};
///
/// struct Admin;
/// impl Capability for Admin { const NAME: &'static str = "admin"; }
///
/// // This will not compile — Proof's fields are private:
/// let fake = Proof::<Admin>::new();
/// ```
///
/// At runtime, `Proof<C>` compiles away entirely:
/// ```
/// use mcp_authorization::{Capability, Proof};
/// assert_eq!(std::mem::size_of::<Proof<Admin>>(), 0);
///
/// struct Admin;
/// impl Capability for Admin { const NAME: &'static str = "admin"; }
/// ```
pub struct Proof<C: Capability> {
    _marker: PhantomData<C>,
}

// Proof is Copy — it's zero-sized, so this is free.
impl<C: Capability> Clone for Proof<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: Capability> Copy for Proof<C> {}

impl<C: Capability> std::fmt::Debug for Proof<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Proof<{}>", C::NAME)
    }
}

/// Per-request authorization context.
///
/// Built by middleware (e.g. from JWT claims) and stored in rmcp's
/// `RequestContext::extensions`. Use rmcp's `Extension<AuthContext>`
/// extractor to access it in tool handlers.
///
/// ```
/// use mcp_authorization::{AuthContext, Capability, Proof};
///
/// struct BackwardRouting;
/// impl Capability for BackwardRouting {
///     const NAME: &'static str = "backward_routing";
/// }
///
/// let auth = AuthContext::new(vec!["backward_routing"]);
/// let proof: Proof<BackwardRouting> = auth.require::<BackwardRouting>().unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct AuthContext {
    capabilities: Arc<HashSet<String>>,
}

impl AuthContext {
    /// Create a new `AuthContext` from an iterable of capability names.
    pub fn new(caps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            capabilities: Arc::new(caps.into_iter().map(Into::into).collect()),
        }
    }

    /// Try to obtain a `Proof<C>`. Returns `Some(Proof)` if the user has
    /// the capability, `None` otherwise.
    ///
    /// This is the **only way** to construct a `Proof<C>`.
    pub fn check<C: Capability>(&self) -> Option<Proof<C>> {
        if self.capabilities.contains(C::NAME) {
            Some(Proof {
                _marker: PhantomData,
            })
        } else {
            None
        }
    }

    /// Like [`check`](Self::check), but returns an `McpError` on failure.
    pub fn require<C: Capability>(&self) -> Result<Proof<C>, rmcp::ErrorData> {
        self.check::<C>().ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                format!("missing required capability: {}", C::NAME),
                None,
            )
        })
    }

    /// String-based capability query for runtime schema shaping.
    pub fn has(&self, name: &str) -> bool {
        self.capabilities.contains(name)
    }

    /// Returns the set of capability names this context holds.
    pub fn capability_names(&self) -> &HashSet<String> {
        &self.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ManageWorkflows;
    impl Capability for ManageWorkflows {
        const NAME: &'static str = "manage_workflows";
    }

    struct BackwardRouting;
    impl Capability for BackwardRouting {
        const NAME: &'static str = "backward_routing";
    }

    struct Admin;
    impl Capability for Admin {
        const NAME: &'static str = "admin";
    }

    #[test]
    fn proof_is_zero_sized() {
        assert_eq!(std::mem::size_of::<Proof<ManageWorkflows>>(), 0);
        assert_eq!(std::mem::size_of::<Proof<BackwardRouting>>(), 0);
    }

    #[test]
    fn check_returns_proof_when_capable() {
        let auth = AuthContext::new(vec!["manage_workflows", "backward_routing"]);
        assert!(auth.check::<ManageWorkflows>().is_some());
        assert!(auth.check::<BackwardRouting>().is_some());
    }

    #[test]
    fn check_returns_none_when_not_capable() {
        let auth = AuthContext::new(vec!["manage_workflows"]);
        assert!(auth.check::<BackwardRouting>().is_none());
    }

    #[test]
    fn require_returns_error_when_not_capable() {
        let auth = AuthContext::new(Vec::<String>::new());
        let err = auth.require::<Admin>().unwrap_err();
        assert!(err.message.contains("admin"));
    }

    #[test]
    fn has_checks_by_string_name() {
        let auth = AuthContext::new(vec!["manage_workflows"]);
        assert!(auth.has("manage_workflows"));
        assert!(!auth.has("admin"));
    }

    #[test]
    fn empty_context_has_no_capabilities() {
        let auth = AuthContext::new(Vec::<String>::new());
        assert!(!auth.has("anything"));
        assert!(auth.check::<Admin>().is_none());
    }

    #[test]
    fn proof_is_copyable() {
        let auth = AuthContext::new(vec!["manage_workflows"]);
        let proof = auth.check::<ManageWorkflows>().unwrap();
        let _copy = proof;
        let _another = proof; // still valid — Copy
    }
}

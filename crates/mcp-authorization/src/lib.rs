//! # mcp-authorization
//!
//! Type-state authorization for MCP servers, built on top of
//! [rmcp](https://docs.rs/rmcp) (the official Rust MCP SDK).
//!
//! ## Core idea
//!
//! In Ruby, `can?(:flag)` is a runtime policy check you could forget.
//! In Rust, `Proof<C>` is a zero-sized token that can only be obtained
//! by verifying a capability — if a function demands it, the compiler
//! refuses to build code that skips the check.
//!
//! ## Three layers of authorization
//!
//! | Layer | Ruby gem | Rust crate |
//! |-------|----------|-----------|
//! | Tool visibility | `authorization :flag` | `authorize("tool", "flag")` |
//! | Field shaping | `@requires(:flag)` on param | `#[requires("flag")]` on field |
//! | Variant shaping | `@requires(:flag)` on variant | `#[requires("flag")]` on enum variant |
//!
//! ## Quick example
//!
//! ```rust
//! use mcp_authorization::{Capability, Proof, AuthContext};
//!
//! // Define a capability as a zero-sized type
//! struct Admin;
//! impl Capability for Admin {
//!     const NAME: &'static str = "admin";
//! }
//!
//! // A function that REQUIRES admin proof to call
//! fn delete_everything(_proof: Proof<Admin>) -> String {
//!     "deleted".to_string()
//! }
//!
//! // At runtime: the check happens once, the proof flows through
//! let auth = AuthContext::new(vec!["admin"]);
//! if let Some(proof) = auth.check::<Admin>() {
//!     delete_everything(proof); // compiles
//! }
//!
//! // Without the proof, this would not compile:
//! // delete_everything(???); // error[E0061]: missing argument
//! ```

pub mod capability;
pub mod metadata;
pub mod registry;
pub mod schema;
pub mod server;

// Re-exports for convenience
pub use capability::{AuthContext, Capability, Proof};
pub use metadata::AuthSchemaMetadata;
pub use registry::{AuthToolDef, AuthToolRegistry};
pub use schema::SchemaShaper;
pub use server::AuthorizedServer;

// Re-export the derive macro
pub use mcp_authorization_macros::AuthSchema;

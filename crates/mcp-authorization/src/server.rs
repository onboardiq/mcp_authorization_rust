use std::future::Future;

use rmcp::{
    handler::server::ServerHandler,
    model::*,
    service::{MaybeSendFuture, NotificationContext, RequestContext, RoleServer},
    ErrorData as McpError,
};
use schemars::JsonSchema;

use crate::metadata::AuthSchemaMetadata;
use crate::provider::{AuthProvider, DenyByDefault};
use crate::registry::AuthToolRegistry;

/// Typestate marker: no auth source has been chosen yet.
///
/// An `AuthorizedServer<S, NoAuth>` is a *builder* — it deliberately does **not**
/// implement [`ServerHandler`], so it cannot be served over any transport. You
/// must first choose how requests get an [`AuthContext`](crate::AuthContext):
/// [`with_auth`](AuthorizedServer::with_auth) (required for network transports)
/// or [`deny_by_default`](AuthorizedServer::deny_by_default) (ergonomic for
/// stdio/dev).
pub struct NoAuth;

/// Typestate marker: an auth source `P` is wired in. Only in this state does
/// [`AuthorizedServer`] implement [`ServerHandler`].
pub struct Authorized<P: AuthProvider>(pub(crate) P);

/// A `ServerHandler` wrapper that adds authorization-based schema shaping.
///
/// Wraps any inner `ServerHandler` and intercepts `list_tools` / `call_tool` to
/// filter tools and shape schemas based on the request's
/// [`AuthContext`](crate::AuthContext).
///
/// # Compile-time guarantee
///
/// In the spirit of [`Proof<C>`](crate::Proof) — which makes skipping a
/// capability check *uncompilable* — forgetting to wire authentication is a
/// **build error**, not a runtime panic. `ServerHandler` is implemented only for
/// `AuthorizedServer<S, Authorized<P>>`, so a server with no auth source chosen
/// cannot be served:
///
/// ```compile_fail
/// use mcp_authorization::AuthorizedServer;
/// use rmcp::handler::server::ServerHandler;
/// use rmcp::model::{ServerInfo, ServerCapabilities, Implementation};
///
/// struct Inner;
/// impl ServerHandler for Inner {
///     fn get_info(&self) -> ServerInfo {
///         ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
///             .with_server_info(Implementation::new("inner", "0.0.0"))
///     }
/// }
/// fn requires_handler<T: ServerHandler>(_: T) {}
///
/// // No auth source chosen → not a ServerHandler → does not compile.
/// requires_handler(AuthorizedServer::new(Inner));
/// ```
///
/// Choosing an auth source makes it servable:
///
/// ```
/// use mcp_authorization::AuthorizedServer;
/// use rmcp::handler::server::ServerHandler;
/// use rmcp::model::{ServerInfo, ServerCapabilities, Implementation};
///
/// struct Inner;
/// impl ServerHandler for Inner {
///     fn get_info(&self) -> ServerInfo {
///         ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
///             .with_server_info(Implementation::new("inner", "0.0.0"))
///     }
/// }
/// fn requires_handler<T: ServerHandler>(_: T) {}
///
/// // deny_by_default() (or with_auth(..)) yields a real ServerHandler.
/// requires_handler(AuthorizedServer::new(Inner).deny_by_default());
/// ```
pub struct AuthorizedServer<S: ServerHandler, A = NoAuth> {
    inner: S,
    registry: AuthToolRegistry,
    auth: A,
}

impl<S: ServerHandler> AuthorizedServer<S, NoAuth> {
    /// Start building an authorized server. No auth source is chosen yet, so the
    /// result is not yet a [`ServerHandler`] — call
    /// [`with_auth`](Self::with_auth) or [`deny_by_default`](Self::deny_by_default).
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            registry: AuthToolRegistry::new(),
            auth: NoAuth,
        }
    }
}

// Builder operations available in any auth state.
impl<S: ServerHandler, A> AuthorizedServer<S, A> {
    /// Register a tool with typed input/output for schema generation and
    /// authorization metadata.
    pub fn register<I, O>(
        mut self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self
    where
        I: JsonSchema + AuthSchemaMetadata + serde::de::DeserializeOwned + 'static,
        O: JsonSchema + AuthSchemaMetadata + serde::Serialize + 'static,
    {
        self.registry.register_typed::<I, O>(name, description);
        self
    }

    /// Set tool-level authorization for a named tool. The tool is hidden from
    /// `list_tools` if the request's `AuthContext` lacks this capability.
    pub fn authorize(mut self, tool_name: &str, capability: &'static str) -> Self {
        self.registry.set_authorization(tool_name, capability);
        self
    }

    /// Choose an explicit auth source. **Required before serving any network
    /// transport.** Transitions the server into the servable
    /// [`Authorized`] state.
    ///
    /// `provider` is anything implementing [`AuthProvider`], including a closure
    /// `Fn(&RequestContext<RoleServer>) -> AuthContext`.
    pub fn with_auth<P: AuthProvider>(self, provider: P) -> AuthorizedServer<S, Authorized<P>> {
        AuthorizedServer {
            inner: self.inner,
            registry: self.registry,
            auth: Authorized(provider),
        }
    }

    /// Install [`DenyByDefault`]: use an `AuthContext` injected by middleware if
    /// present, otherwise resolve to [`AuthContext::empty`](crate::AuthContext::empty).
    ///
    /// The ergonomic choice for stdio / local / dev: the server is immediately
    /// servable and an unauthenticated client sees the least-privileged view
    /// (only ungated tools) rather than an error.
    pub fn deny_by_default(self) -> AuthorizedServer<S, Authorized<DenyByDefault>> {
        self.with_auth(DenyByDefault)
    }

    /// Get a reference to the inner handler.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get a reference to the authorization registry.
    pub fn registry(&self) -> &AuthToolRegistry {
        &self.registry
    }
}

/// Sealed marker for "this server has an auth source and may be served".
///
/// Implemented only for [`Authorized`]. Use it as a bound (e.g. in your own
/// serve helpers) to require — at compile time, with a readable error — that an
/// auth source was chosen before serving.
#[diagnostic::on_unimplemented(
    message = "this `AuthorizedServer` has no auth source, so it cannot be served",
    note = "call `.with_auth(provider)` (required before any network transport), \
            or `.deny_by_default()` for stdio/local/dev (least-privilege unless \
            middleware injects an AuthContext)"
)]
pub trait ReadyToServe {}
impl<P: AuthProvider> ReadyToServe for Authorized<P> {}

impl<S: ServerHandler, P: AuthProvider + 'static> ServerHandler for AuthorizedServer<S, Authorized<P>> {
    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + MaybeSendFuture + '_ {
        async move {
            // Resolve via the provider — never errors. No context → deny-by-default.
            let auth = self.auth.0.auth_for(&context);
            let tools = self.registry.materialize(&auth);
            Ok(ListToolsResult {
                tools,
                ..Default::default()
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, McpError>> + MaybeSendFuture + '_ {
        async move {
            // Always enforce tool-level visibility against the resolved context
            // (previously skipped when no context was present — a silent gap).
            let auth = self.auth.0.auth_for(&context);
            if !self.registry.is_visible(&request.name, &auth) {
                return Err(McpError::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    format!("tool not found: {}", request.name),
                    None,
                ));
            }
            self.inner.call_tool(request, context).await
        }
    }

    // --- Delegate everything else to inner ---

    fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.initialize(request, context)
    }

    fn ping(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.ping(context)
    }

    fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CompleteResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.complete(request, context)
    }

    fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.set_level(request, context)
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.get_prompt(request, context)
    }

    fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.list_prompts(request, context)
    }

    fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.list_resources(request, context)
    }

    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, McpError>> + MaybeSendFuture + '_
    {
        self.inner.list_resource_templates(request, context)
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.read_resource(request, context)
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.subscribe(request, context)
    }

    fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + MaybeSendFuture + '_ {
        self.inner.unsubscribe(request, context)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CustomResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.on_custom_request(request, context)
    }

    fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_cancelled(notification, context)
    }

    fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_progress(notification, context)
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_initialized(context)
    }

    fn on_roots_list_changed(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_roots_list_changed(context)
    }

    fn on_custom_notification(
        &self,
        notification: CustomNotification,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + MaybeSendFuture + '_ {
        self.inner.on_custom_notification(notification, context)
    }

    fn enqueue_task(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CreateTaskResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.enqueue_task(request, context)
    }

    fn list_tasks(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListTasksResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.list_tasks(request, context)
    }

    fn get_task_info(
        &self,
        request: GetTaskInfoParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetTaskResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.get_task_info(request, context)
    }

    fn get_task_result(
        &self,
        request: GetTaskResultParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetTaskPayloadResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.get_task_result(request, context)
    }

    fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CancelTaskResult, McpError>> + MaybeSendFuture + '_ {
        self.inner.cancel_task(request, context)
    }
}

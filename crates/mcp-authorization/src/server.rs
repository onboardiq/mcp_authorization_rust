use std::future::Future;

use rmcp::{
    ErrorData as McpError,
    handler::server::ServerHandler,
    model::*,
    service::{MaybeSendFuture, NotificationContext, RequestContext, RoleServer},
};
use schemars::JsonSchema;

use crate::capability::AuthContext;
use crate::metadata::AuthSchemaMetadata;
use crate::registry::AuthToolRegistry;

/// A `ServerHandler` wrapper that adds authorization-based schema shaping.
///
/// Wraps any inner `ServerHandler` and intercepts `list_tools` and
/// `call_tool` to filter tools and shape schemas based on the user's
/// `AuthContext` (stored in `RequestContext::extensions`).
///
/// ```ignore
/// let server = AuthorizedServer::new(MyHandler)
///     .register::<AdvanceStepInput, AdvanceStepOutput>(
///         "advance_step",
///         "Advance an applicant",
///     )
///     .authorize("advance_step", "manage_workflows");
/// ```
pub struct AuthorizedServer<S: ServerHandler> {
    inner: S,
    registry: AuthToolRegistry,
}

impl<S: ServerHandler> AuthorizedServer<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            registry: AuthToolRegistry::new(),
        }
    }

    /// Register a tool with typed input/output for schema generation
    /// and authorization metadata.
    pub fn register<I, O>(
        mut self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self
    where
        I: JsonSchema + AuthSchemaMetadata + serde::de::DeserializeOwned + 'static,
        O: JsonSchema + AuthSchemaMetadata + serde::Serialize + 'static,
    {
        self.registry
            .register_typed::<I, O>(name, description);
        self
    }

    /// Set tool-level authorization for a named tool.
    /// The tool will be hidden from `list_tools` if the user lacks this capability.
    pub fn authorize(mut self, tool_name: &str, capability: &'static str) -> Self {
        self.registry.set_authorization(tool_name, capability);
        self
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

impl<S: ServerHandler> ServerHandler for AuthorizedServer<S> {
    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + MaybeSendFuture + '_ {
        async move {
            let auth = context
                .extensions
                .get::<AuthContext>()
                .ok_or_else(|| McpError::internal_error("missing AuthContext in extensions", None))?;

            let tools = self.registry.materialize(auth);
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
            // Check tool-level authorization before delegating
            if let Some(auth) = context.extensions.get::<AuthContext>() {
                if !self.registry.is_visible(&request.name, auth) {
                    return Err(McpError::new(
                        ErrorCode::METHOD_NOT_FOUND,
                        format!("tool not found: {}", request.name),
                        None,
                    ));
                }
            }

            // Delegate actual execution to the inner handler
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

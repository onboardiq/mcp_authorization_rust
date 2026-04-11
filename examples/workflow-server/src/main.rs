//! Workflow MCP server demonstrating type-state authorization.
//!
//! This mirrors the Ruby handler-example's `advance_step` tool.
//! Run with: `cargo run -p workflow-server`

use mcp_authorization::{AuthContext, AuthSchema, AuthorizedServer, Capability, Proof};
use rmcp::{
    handler::server::{
        wrapper::Parameters,
        common::Extension,
        ServerHandler,
    },
    model::*,
    tool,
    ErrorData as McpError, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Step 1: Define capabilities as zero-sized types
// ---------------------------------------------------------------------------

struct ManageWorkflows;
impl Capability for ManageWorkflows {
    const NAME: &'static str = "manage_workflows";
}

struct BackwardRouting;
impl Capability for BackwardRouting {
    const NAME: &'static str = "backward_routing";
}

// ---------------------------------------------------------------------------
// Step 2: Define input with field-level authorization
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema, AuthSchema)]
struct AdvanceStepInput {
    /// The applicant to advance (use fetch_latest_applicant to get this)
    pub applicant_id: String,
    /// Target workflow
    pub workflow_id: String,
    /// Target stage for rerouting — only visible to managers
    #[requires("backward_routing")]
    pub stage_id: Option<String>,
    /// Reason for rerouting — only visible to managers
    #[requires("backward_routing")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Step 3: Define output with variant-level authorization
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, JsonSchema, AuthSchema)]
#[serde(tag = "type")]
enum AdvanceStepOutput {
    Success {
        applicant_id: String,
        current_stage: String,
    },
    /// Only returned when the user has backward_routing capability
    #[requires("backward_routing")]
    ReroutedSuccess {
        applicant_id: String,
        previous_stage: String,
        current_stage: String,
        audit_trail: Vec<String>,
    },
    Error {
        code: String,
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Step 4: The server handler
// ---------------------------------------------------------------------------

struct WorkflowServer;

impl WorkflowServer {
    /// This function CANNOT be called without a Proof<BackwardRouting>.
    /// The compiler enforces it. You cannot forget the auth check.
    fn reroute(
        &self,
        _proof: Proof<BackwardRouting>,
        input: &AdvanceStepInput,
    ) -> AdvanceStepOutput {
        let target = input.stage_id.as_deref().unwrap_or("screening");

        AdvanceStepOutput::ReroutedSuccess {
            applicant_id: input.applicant_id.clone(),
            previous_stage: "applied".into(),
            current_stage: target.into(),
            audit_trail: vec![
                format!("Rerouted from applied to {}", target),
                format!(
                    "Reason: {}",
                    input.reason.as_deref().unwrap_or("none given")
                ),
            ],
        }
    }

    fn advance_forward(&self, input: &AdvanceStepInput) -> AdvanceStepOutput {
        AdvanceStepOutput::Success {
            applicant_id: input.applicant_id.clone(),
            current_stage: "screening".into(),
        }
    }
}

#[rmcp::tool_router]
impl WorkflowServer {
    /// Advance an applicant in their workflow
    #[tool(name = "advance_step")]
    fn advance_step(
        &self,
        Parameters(input): Parameters<AdvanceStepInput>,
        Extension(auth): Extension<AuthContext>,
    ) -> Result<CallToolResult, McpError> {
        // Type-state in action: Proof<BackwardRouting> is required by reroute()
        let result = if let Some(proof) = auth.check::<BackwardRouting>() {
            self.reroute(proof, &input)
        } else {
            self.advance_forward(&input)
        };

        let json = serde_json::to_string(&result)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

#[rmcp::tool_handler]
impl ServerHandler for WorkflowServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("workflow-server", "0.1.0"))
    }
}

// ---------------------------------------------------------------------------
// Step 5: Wire it up
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // The AuthorizedServer wraps the inner handler and intercepts
    // list_tools to shape schemas per-user.
    let server = AuthorizedServer::new(WorkflowServer)
        .register::<AdvanceStepInput, AdvanceStepOutput>(
            "advance_step",
            "Advance an applicant in their workflow",
        )
        .authorize("advance_step", "manage_workflows");

    // For this demo, we use stdio transport.
    // In production, you'd use StreamableHTTP with auth middleware
    // that extracts AuthContext from JWT headers.
    eprintln!("Workflow MCP server starting on stdio...");
    eprintln!("Tools registered with type-state authorization.");
    eprintln!(
        "  - advance_step: requires '{}' (tool-level)",
        ManageWorkflows::NAME
    );
    eprintln!(
        "  - stage_id, reason fields: require '{}' (field-level)",
        BackwardRouting::NAME
    );

    let transport = rmcp::transport::io::stdio();
    let service = server
        .serve(transport)
        .await
        .expect("failed to start server");
    service.waiting().await.expect("server error");
}

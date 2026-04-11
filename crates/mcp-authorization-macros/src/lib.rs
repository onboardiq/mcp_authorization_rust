mod auth_schema;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

/// Derive macro that generates `AuthSchemaMetadata` implementations.
///
/// Reads `#[requires("capability_name")]` attributes from struct fields
/// or enum variants and produces a static requirements table used by
/// the schema shaper to filter fields/variants per-request.
///
/// # On structs (input schema shaping)
///
/// ```ignore
/// #[derive(AuthSchema)]
/// struct AdvanceStepInput {
///     pub applicant_id: String,
///     #[requires("backward_routing")]
///     pub stage_id: Option<String>,
/// }
/// ```
///
/// # On enums (output variant shaping)
///
/// ```ignore
/// #[derive(AuthSchema)]
/// enum AdvanceStepOutput {
///     Success { applicant_id: String },
///     #[requires("backward_routing")]
///     ReroutedSuccess { applicant_id: String, previous_stage: String },
/// }
/// ```
#[proc_macro_derive(AuthSchema, attributes(requires))]
pub fn derive_auth_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    auth_schema::derive_auth_schema(input).into()
}

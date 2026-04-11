use std::sync::Arc;

use schemars::JsonSchema;
use serde_json::Value;

use crate::capability::AuthContext;
use crate::metadata::AuthSchemaMetadata;

/// Shapes JSON Schema at runtime by removing fields or variants that the
/// current user lacks capabilities for.
///
/// This is the Rust equivalent of `RbsSchemaCompiler` in the Ruby gem:
/// the full schema is generated once at compile time (via `schemars`),
/// then filtered per-request based on the user's `AuthContext`.
pub struct SchemaShaper;

impl SchemaShaper {
    /// Generate a shaped input schema for type `T`.
    ///
    /// Starts from the full schemars-generated schema, then removes
    /// properties whose `AuthSchemaMetadata` requirements are not
    /// satisfied by the given `AuthContext`.
    pub fn shape_input<T: JsonSchema + AuthSchemaMetadata + 'static>(
        auth: &AuthContext,
    ) -> Arc<serde_json::Map<String, Value>> {
        let full_schema = rmcp::handler::server::tool::schema_for_type::<T>();
        let requirements = T::requirements();

        // Fast path: no auth-gated fields
        if requirements.is_empty() || requirements.iter().all(|(_, cap)| auth.has(cap)) {
            return full_schema;
        }

        let fields_to_remove: Vec<&str> = requirements
            .iter()
            .filter(|(_, cap)| !auth.has(cap))
            .map(|(field, _)| *field)
            .collect();

        let mut schema = (*full_schema).clone();
        remove_properties(&mut schema, &fields_to_remove);
        Arc::new(schema)
    }

    /// Generate a shaped output schema for type `T`.
    ///
    /// Removes `oneOf`/`anyOf` variants whose `AuthSchemaMetadata`
    /// requirements are not satisfied.
    pub fn shape_output<T: JsonSchema + AuthSchemaMetadata + 'static>(
        auth: &AuthContext,
    ) -> Option<Arc<serde_json::Map<String, Value>>> {
        let full_schema = rmcp::handler::server::tool::schema_for_output::<T>().ok()?;
        let requirements = T::requirements();

        if requirements.is_empty() || requirements.iter().all(|(_, cap)| auth.has(cap)) {
            return Some(full_schema);
        }

        let variants_to_remove: Vec<&str> = requirements
            .iter()
            .filter(|(_, cap)| !auth.has(cap))
            .map(|(variant, _)| *variant)
            .collect();

        let mut schema = (*full_schema).clone();
        remove_variants(&mut schema, &variants_to_remove);
        Some(Arc::new(schema))
    }
}

/// Remove properties from a JSON Schema object and its `required` array.
fn remove_properties(schema: &mut serde_json::Map<String, Value>, fields: &[&str]) {
    // Remove from top-level "properties"
    if let Some(Value::Object(props)) = schema.get_mut("properties") {
        for field in fields {
            props.remove(*field);
        }
    }

    // Remove from "required" array
    if let Some(Value::Array(required)) = schema.get_mut("required") {
        required.retain(|v| {
            v.as_str()
                .map_or(true, |name| !fields.contains(&name))
        });
    }

    // Handle $defs-based schemas: if properties are referenced via $ref,
    // also check nested allOf/anyOf/oneOf at the top level
    for key in &["allOf", "anyOf", "oneOf"] {
        if let Some(Value::Array(variants)) = schema.get_mut(*key) {
            for variant in variants.iter_mut() {
                if let Value::Object(obj) = variant {
                    remove_properties(obj, fields);
                }
            }
        }
    }
}

/// Remove variants from oneOf/anyOf in a JSON Schema.
///
/// Matches variants by checking:
/// 1. `title` field
/// 2. `$ref` ending (e.g. `#/$defs/ReroutedSuccess`)
/// 3. Internally tagged enum discriminator value
fn remove_variants(schema: &mut serde_json::Map<String, Value>, variants: &[&str]) {
    for key in &["oneOf", "anyOf"] {
        if let Some(Value::Array(items)) = schema.get_mut(*key) {
            items.retain(|item| {
                let name = variant_name(item);
                match name {
                    Some(n) => !variants.contains(&n.as_str()),
                    None => true, // keep unrecognized variants
                }
            });
        }
    }

    // Also clean up $defs — remove definitions that are no longer referenced
    if let Some(Value::Object(defs)) = schema.get("$defs") {
        let def_names: Vec<String> = defs.keys().cloned().collect();
        let schema_str = serde_json::to_string(&schema).unwrap_or_default();
        let unused: Vec<String> = def_names
            .into_iter()
            .filter(|name| {
                let ref_str = format!("#/$defs/{}", name);
                !schema_str.contains(&ref_str) || variants.contains(&name.as_str())
            })
            .collect();

        if !unused.is_empty() {
            if let Some(Value::Object(defs)) = schema.get_mut("$defs") {
                for name in &unused {
                    // Only remove if it's a variant we're filtering
                    if variants.contains(&name.as_str()) {
                        defs.remove(name);
                    }
                }
            }
        }
    }
}

/// Extract a variant's name from its JSON Schema representation.
fn variant_name(item: &Value) -> Option<String> {
    let obj = item.as_object()?;

    // Check "title" field first
    if let Some(Value::String(title)) = obj.get("title") {
        return Some(title.clone());
    }

    // Check $ref (e.g. "#/$defs/ReroutedSuccess")
    if let Some(Value::String(ref_str)) = obj.get("$ref") {
        return ref_str.rsplit('/').next().map(String::from);
    }

    // Check internally tagged enum: {"properties": {"type": {"const": "VariantName"}}}
    if let Some(Value::Object(props)) = obj.get("properties") {
        if let Some(Value::Object(type_prop)) = props.get("type") {
            if let Some(Value::String(const_val)) = type_prop.get("const") {
                return Some(const_val.clone());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthSchemaMetadata;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, JsonSchema)]
    #[allow(dead_code)]
    struct TestInput {
        pub name: String,
        pub public_field: String,
        pub secret_field: Option<String>,
        pub admin_field: Option<i32>,
    }

    impl AuthSchemaMetadata for TestInput {
        fn requirements() -> &'static [(&'static str, &'static str)] {
            &[
                ("secret_field", "view_secrets"),
                ("admin_field", "admin"),
            ]
        }
    }

    #[test]
    fn shape_input_removes_unauthorized_fields() {
        let auth = AuthContext::new(Vec::<String>::new());
        let schema = SchemaShaper::shape_input::<TestInput>(&auth);

        let props = schema.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(props.contains_key("public_field"));
        assert!(!props.contains_key("secret_field"));
        assert!(!props.contains_key("admin_field"));
    }

    #[test]
    fn shape_input_keeps_authorized_fields() {
        let auth = AuthContext::new(vec!["view_secrets", "admin"]);
        let schema = SchemaShaper::shape_input::<TestInput>(&auth);

        let props = schema.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(props.contains_key("secret_field"));
        assert!(props.contains_key("admin_field"));
    }

    #[test]
    fn shape_input_partial_authorization() {
        let auth = AuthContext::new(vec!["view_secrets"]);
        let schema = SchemaShaper::shape_input::<TestInput>(&auth);

        let props = schema.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("secret_field"));
        assert!(!props.contains_key("admin_field"));
    }

    #[derive(Deserialize, JsonSchema)]
    #[allow(dead_code)]
    struct NoAuthInput {
        pub name: String,
    }

    impl AuthSchemaMetadata for NoAuthInput {
        fn requirements() -> &'static [(&'static str, &'static str)] {
            &[]
        }
    }

    #[test]
    fn shape_input_no_requirements_returns_full_schema() {
        let auth = AuthContext::new(Vec::<String>::new());
        let shaped = SchemaShaper::shape_input::<NoAuthInput>(&auth);
        let full = rmcp::handler::server::tool::schema_for_type::<NoAuthInput>();
        // Same Arc — no clone happened
        assert!(Arc::ptr_eq(&shaped, &full));
    }

    #[test]
    fn shape_input_removes_from_required_array() {
        let auth = AuthContext::new(Vec::<String>::new());
        let schema = SchemaShaper::shape_input::<TestInput>(&auth);

        if let Some(Value::Array(required)) = schema.get("required") {
            let names: Vec<&str> = required
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert!(!names.contains(&"secret_field"));
            assert!(!names.contains(&"admin_field"));
        }
    }

    // Output variant filtering tests

    #[derive(Serialize, JsonSchema)]
    #[serde(tag = "type")]
    #[allow(dead_code)]
    enum TestOutput {
        Success { id: String },
        AdminDetail { id: String, secret: String },
        Error { message: String },
    }

    impl AuthSchemaMetadata for TestOutput {
        fn requirements() -> &'static [(&'static str, &'static str)] {
            &[("AdminDetail", "admin")]
        }
    }

    #[test]
    fn shape_output_removes_unauthorized_variants() {
        let auth = AuthContext::new(Vec::<String>::new());
        let schema = SchemaShaper::shape_output::<TestOutput>(&auth);

        if let Some(schema) = schema {
            let schema_str = serde_json::to_string(&*schema).unwrap();
            assert!(!schema_str.contains("AdminDetail"));
            assert!(schema_str.contains("Success"));
            assert!(schema_str.contains("Error"));
        }
    }

    #[test]
    fn shape_output_keeps_all_when_authorized() {
        let auth = AuthContext::new(vec!["admin"]);
        let schema = SchemaShaper::shape_output::<TestOutput>(&auth);

        if let Some(schema) = schema {
            let schema_str = serde_json::to_string(&*schema).unwrap();
            assert!(schema_str.contains("AdminDetail"));
            assert!(schema_str.contains("Success"));
        }
    }
}

use std::collections::HashMap;
use std::sync::Arc;

use schemars::JsonSchema;
use serde_json::Value;

use crate::capability::AuthContext;
use crate::metadata::AuthSchemaMetadata;

/// A tool definition with authorization metadata attached.
pub struct AuthToolDef {
    /// The base rmcp tool (name, description, full schemas)
    pub base_tool: rmcp::model::Tool,
    /// Tool-level gate: entire tool hidden if user lacks this capability
    pub authorization: Option<&'static str>,
    /// Field-level requirements for input schema shaping
    pub input_requirements: &'static [(&'static str, &'static str)],
    /// Variant-level requirements for output schema shaping
    pub output_requirements: &'static [(&'static str, &'static str)],
}

/// Registry of tools with authorization metadata.
///
/// On each request, `materialize` produces per-user tool lists with
/// shaped schemas — the same concept as `ToolRegistry.tool_classes_for`
/// in the Ruby gem.
pub struct AuthToolRegistry {
    tools: HashMap<String, AuthToolDef>,
    /// Insertion order for deterministic tool listing
    order: Vec<String>,
}

impl AuthToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Register a tool with its authorization metadata.
    pub fn register(&mut self, def: AuthToolDef) {
        let name = def.base_tool.name.to_string();
        if !self.tools.contains_key(&name) {
            self.order.push(name.clone());
        }
        self.tools.insert(name, def);
    }

    /// Register a tool using type information for schema and auth metadata.
    ///
    /// This is the ergonomic builder method:
    /// ```ignore
    /// registry.register_typed::<AdvanceStepInput, AdvanceStepOutput>(
    ///     "advance_step",
    ///     "Advance an applicant in their workflow",
    /// );
    /// ```
    pub fn register_typed<I, O>(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) where
        I: JsonSchema + AuthSchemaMetadata + serde::de::DeserializeOwned + 'static,
        O: JsonSchema + AuthSchemaMetadata + serde::Serialize + 'static,
    {
        let name = name.into();
        let full_input = rmcp::handler::server::tool::schema_for_type::<I>();
        let full_output = rmcp::handler::server::tool::schema_for_output::<O>().ok();

        let mut tool = rmcp::model::Tool::new(name.clone(), description.into(), full_input);
        if let Some(output) = full_output {
            tool = tool.with_raw_output_schema(output);
        }

        self.register(AuthToolDef {
            base_tool: tool,
            authorization: None,
            input_requirements: I::requirements(),
            output_requirements: O::requirements(),
        });
    }

    /// Set tool-level authorization for a named tool.
    pub fn set_authorization(&mut self, tool_name: &str, capability: &'static str) {
        if let Some(def) = self.tools.get_mut(tool_name) {
            def.authorization = Some(capability);
        }
    }

    /// Materialize tools for a specific user: filter hidden tools, shape schemas.
    ///
    /// This is the per-request method, equivalent to `ToolRegistry.tool_classes_for`
    /// in the Ruby gem.
    pub fn materialize(&self, auth: &AuthContext) -> Vec<rmcp::model::Tool> {
        self.order
            .iter()
            .filter_map(|name| {
                let def = self.tools.get(name)?;

                // Tool-level gate
                if let Some(required) = def.authorization {
                    if !auth.has(required) {
                        return None;
                    }
                }

                let mut tool = def.base_tool.clone();

                // Shape input schema
                if !def.input_requirements.is_empty() {
                    let fields_to_remove: Vec<&str> = def
                        .input_requirements
                        .iter()
                        .filter(|(_, cap)| !auth.has(cap))
                        .map(|(field, _)| *field)
                        .collect();

                    if !fields_to_remove.is_empty() {
                        let mut schema = (*tool.input_schema).clone();
                        remove_properties(&mut schema, &fields_to_remove);
                        tool.input_schema = Arc::new(schema);
                    }
                }

                // Shape output schema
                if !def.output_requirements.is_empty() {
                    if let Some(ref output) = tool.output_schema {
                        let variants_to_remove: Vec<&str> = def
                            .output_requirements
                            .iter()
                            .filter(|(_, cap)| !auth.has(cap))
                            .map(|(variant, _)| *variant)
                            .collect();

                        if !variants_to_remove.is_empty() {
                            let mut schema = (**output).clone();
                            remove_variants(&mut schema, &variants_to_remove);
                            tool.output_schema = Some(Arc::new(schema));
                        }
                    }
                }

                Some(tool)
            })
            .collect()
    }

    /// Check if a tool is visible to the given auth context.
    pub fn is_visible(&self, tool_name: &str, auth: &AuthContext) -> bool {
        self.tools.get(tool_name).map_or(false, |def| {
            def.authorization.map_or(true, |cap| auth.has(cap))
        })
    }

    /// Get a tool definition by name (unshaped).
    pub fn get(&self, tool_name: &str) -> Option<&AuthToolDef> {
        self.tools.get(tool_name)
    }
}

impl Default for AuthToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Schema manipulation helpers (duplicated from schema.rs to avoid
// coupling the registry to the generic SchemaShaper)

fn remove_properties(schema: &mut serde_json::Map<String, Value>, fields: &[&str]) {
    if let Some(Value::Object(props)) = schema.get_mut("properties") {
        for field in fields {
            props.remove(*field);
        }
    }
    if let Some(Value::Array(required)) = schema.get_mut("required") {
        required.retain(|v| v.as_str().map_or(true, |name| !fields.contains(&name)));
    }
}

fn remove_variants(schema: &mut serde_json::Map<String, Value>, variants: &[&str]) {
    for key in &["oneOf", "anyOf"] {
        if let Some(Value::Array(items)) = schema.get_mut(*key) {
            items.retain(|item| {
                let name = variant_name(item);
                match name {
                    Some(n) => !variants.contains(&n.as_str()),
                    None => true,
                }
            });
        }
    }
}

fn variant_name(item: &Value) -> Option<String> {
    let obj = item.as_object()?;
    if let Some(Value::String(title)) = obj.get("title") {
        return Some(title.clone());
    }
    if let Some(Value::String(ref_str)) = obj.get("$ref") {
        return ref_str.rsplit('/').next().map(String::from);
    }
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

    #[derive(serde::Deserialize, JsonSchema)]
    #[allow(dead_code)]
    struct Input {
        pub name: String,
        pub secret: Option<String>,
    }

    impl AuthSchemaMetadata for Input {
        fn requirements() -> &'static [(&'static str, &'static str)] {
            &[("secret", "admin")]
        }
    }

    #[derive(serde::Serialize, JsonSchema)]
    #[serde(tag = "type")]
    #[allow(dead_code)]
    enum Output {
        Ok { id: String },
        AdminOk { id: String, detail: String },
    }

    impl AuthSchemaMetadata for Output {
        fn requirements() -> &'static [(&'static str, &'static str)] {
            &[("AdminOk", "admin")]
        }
    }

    #[test]
    fn materialize_hides_unauthorized_tools() {
        let mut reg = AuthToolRegistry::new();
        reg.register_typed::<Input, Output>("my_tool", "A tool");
        reg.set_authorization("my_tool", "admin");

        let no_auth = AuthContext::new(Vec::<String>::new());
        assert!(reg.materialize(&no_auth).is_empty());

        let admin = AuthContext::new(vec!["admin"]);
        assert_eq!(reg.materialize(&admin).len(), 1);
    }

    #[test]
    fn materialize_shapes_input_schema() {
        let mut reg = AuthToolRegistry::new();
        reg.register_typed::<Input, Output>("my_tool", "A tool");

        let no_auth = AuthContext::new(Vec::<String>::new());
        let tools = reg.materialize(&no_auth);
        let schema = &tools[0].input_schema;
        let props = schema.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("name"));
        assert!(!props.contains_key("secret"));
    }

    #[test]
    fn is_visible_checks_tool_authorization() {
        let mut reg = AuthToolRegistry::new();
        reg.register_typed::<Input, Output>("my_tool", "A tool");
        reg.set_authorization("my_tool", "admin");

        let no_auth = AuthContext::new(Vec::<String>::new());
        assert!(!reg.is_visible("my_tool", &no_auth));

        let admin = AuthContext::new(vec!["admin"]);
        assert!(reg.is_visible("my_tool", &admin));
    }
}

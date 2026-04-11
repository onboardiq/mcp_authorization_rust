use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Lit, Meta};

pub fn derive_auth_schema(input: DeriveInput) -> TokenStream {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let requirements = match &input.data {
        Data::Struct(data) => extract_struct_requirements(&data.fields),
        Data::Enum(data) => extract_enum_requirements(data),
        Data::Union(_) => {
            return syn::Error::new_spanned(&input.ident, "AuthSchema cannot be derived for unions")
                .to_compile_error();
        }
    };

    quote! {
        impl #impl_generics mcp_authorization::AuthSchemaMetadata for #name #ty_generics #where_clause {
            fn requirements() -> &'static [(&'static str, &'static str)] {
                &[#(#requirements),*]
            }
        }
    }
}

/// Extract `#[requires("capability")]` from struct fields.
fn extract_struct_requirements(fields: &Fields) -> Vec<TokenStream> {
    let named = match fields {
        Fields::Named(f) => f,
        _ => return vec![],
    };

    named
        .named
        .iter()
        .filter_map(|field| {
            let field_name = field.ident.as_ref()?;
            let cap = find_requires_attr(&field.attrs)?;
            let field_str = field_name.to_string();
            Some(quote! { (#field_str, #cap) })
        })
        .collect()
}

/// Extract `#[requires("capability")]` from enum variants.
fn extract_enum_requirements(data: &syn::DataEnum) -> Vec<TokenStream> {
    data.variants
        .iter()
        .filter_map(|variant| {
            let cap = find_requires_attr(&variant.attrs)?;
            let variant_str = variant.ident.to_string();
            Some(quote! { (#variant_str, #cap) })
        })
        .collect()
}

/// Look for `#[requires("capability_name")]` in a list of attributes.
/// Returns the capability name string if found.
fn find_requires_attr(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if !attr.path().is_ident("requires") {
            continue;
        }

        // Parse #[requires("capability_name")]
        if let Meta::List(meta_list) = &attr.meta {
            let tokens = meta_list.tokens.clone();
            if let Ok(lit) = syn::parse2::<Lit>(tokens) {
                if let Lit::Str(s) = lit {
                    return Some(s.value());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    // Proc macro tests are done via integration tests / trybuild
}

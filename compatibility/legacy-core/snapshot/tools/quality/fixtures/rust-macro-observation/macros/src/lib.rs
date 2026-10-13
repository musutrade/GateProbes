use proc_macro::TokenStream;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Ident, LitBool, Token,
};

struct Input {
    name: Ident,
    branching: LitBool,
}
impl Parse for Input {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![,]>()?;
        Ok(Self {
            name,
            branching: input.parse()?,
        })
    }
}

#[proc_macro]
pub fn observed_function(input: TokenStream) -> TokenStream {
    let Input { name, branching } = parse_macro_input!(input as Input);
    gate_observation_generator::generate(name, branching.value)
        .generated
        .into()
}

use openssl::ssl::ExtensionContext;

pub const EXTENSION_TYPE_VAL: u16 = 2023;

pub fn extension_context() -> ExtensionContext {
    let mut ctx = ExtensionContext::empty();
    ctx.insert(ExtensionContext::CLIENT_HELLO);
    ctx.insert(ExtensionContext::TLS1_3_ONLY);
    ctx.insert(ExtensionContext::TLS1_3_SERVER_HELLO);
    ctx.insert(ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS);
    ctx.insert(ExtensionContext::TLS1_3_CERTIFICATE_REQUEST);
    ctx.insert(ExtensionContext::TLS1_3_CERTIFICATE);
    ctx
}

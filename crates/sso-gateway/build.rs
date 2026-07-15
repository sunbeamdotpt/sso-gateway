use std::{io, path::PathBuf};

fn main() -> io::Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = manifest_dir.join("..").join("..").join("proto");

    connectrpc_build::Config::new()
        .include_file("_connectrpc.rs")
        .files(&[
            proto_dir.join("iam/v1/common.proto"),
            proto_dir.join("iam/v1/tenant.proto"),
            proto_dir.join("iam/v1/identity.proto"),
            proto_dir.join("iam/v1/application.proto"),
            proto_dir.join("iam/v1/client_credential.proto"),
            proto_dir.join("iam/v1/agent.proto"),
            proto_dir.join("iam/v1/permission.proto"),
            proto_dir.join("iam/v1/federation.proto"),
            proto_dir.join("iam/v1/scim.proto"),
            proto_dir.join("iam/v1/identity_self_service.proto"),
            proto_dir.join("iam/v1/oauth2_consent.proto"),
            proto_dir.join("iam/v1/oauth2_device.proto"),
        ])
        .includes(&[&proto_dir])
        .compile()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(())
}

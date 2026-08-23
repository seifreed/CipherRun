use cipherrun::output::schema::CipherRunSchema;
use cipherrun::scanner::results::OUTPUT_SCHEMA_VERSION;

fn main() -> std::io::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| format!("schemas/cipherrun-scan-{OUTPUT_SCHEMA_VERSION}.schema.json"));
    CipherRunSchema::export_schema(&path)
}

// Output module - Output formatting (JSON, CSV, HTML, Terminal)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    JSON,
    JSONPretty,
    CSV,
    HTML,
    Log,
}

pub mod csv;
pub mod html;
pub mod json;
pub mod schema;
pub mod terminal;
pub mod xml;

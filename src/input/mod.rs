// Input processing module
// Handles various input formats: ASN, CIDR, IP, hostname

pub mod asn_cidr;

pub use asn_cidr::{AsnCidrParser, CidrExpansion, ExpandedInput, InputType};

# Delegated Credentials

CipherRun recognizes and validates the RFC 9345 delegated-credentials
contract, including the wire-level `Certificate` handshake when the OpenSSL
certificate probe is used.

When a caller supplies a captured `CertificateEntry` extension, the pure
`analyze_delegated_credential_entry` parser validates the RFC 9345 length
fields, including the three-byte `SubjectPublicKeyInfo` vector, `valid_time`,
both signature schemes, and the signature vector. For supported RSA PKCS#1,
RSA-PSS, and ECDSA schemes it also verifies the delegation signature over the
RFC 9345 context, certificate, credential, and delegation algorithm. Use
`analyze_delegated_credential_entry_with_role` for client credentials; the
short entry point defaults to the server context.

`CertificateAdvancedTester::test_delegated_credentials()` installs an OpenSSL
message callback, parses the decrypted TLS `Certificate` handshake, and checks
extension type `34` on each `CertificateEntry`. The captured extension is
validated structurally and, for supported RSA/ECDSA schemes, its RFC 9345
signature is verified against the certificate key. If the backend completes a
handshake without exposing a `Certificate` transcript, the probe falls back to
the X.509 `DelegationUsage` prerequisite and reports `not_observed`.

Therefore:

- `certificate_allows_delegation` is a prerequisite signal only.
- `credential_observed: false` is not proof that the peer lacks delegated
  credentials.
- An `observed` entry with an unsupported signature scheme still requires
  signature and certificate-key binding verification before it can be treated
  as trusted; a `verified` entry has passed the offline signature check.
- The rustls certificate parser still exposes only the peer certificate chain;
  wire-level delegated-credential capture is currently implemented by the
  OpenSSL certificate probe.
- Full positive/negative interoperability validation still requires dedicated
  RFC 9345 server fixtures.

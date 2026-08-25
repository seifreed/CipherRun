# Delegated Credentials

CipherRun recognizes the RFC 9345 delegated-credentials contract without
claiming false wire-level support.

When a caller supplies a captured `CertificateEntry` extension, the pure
`analyze_delegated_credential_entry` parser validates the RFC 9345 length
fields, including the three-byte `SubjectPublicKeyInfo` vector, `valid_time`,
both signature schemes, and the signature vector. For supported RSA PKCS#1,
RSA-PSS, and ECDSA schemes it also verifies the delegation signature over the
RFC 9345 context, certificate, credential, and delegation algorithm. Use
`analyze_delegated_credential_entry_with_role` for client credentials; the
short entry point defaults to the server context.

`CertificateAdvancedTester::test_delegated_credentials()` checks the
end-entity certificate for the RFC 9345 `DelegationUsage` extension
(`1.3.6.1.4.1.44363.44`) and reports extension type `34`. The result remains
`not_observed` because a delegated credential is carried in the TLS
`CertificateEntry`, while the rustls/OpenSSL APIs currently used by CipherRun
expose the peer certificate but not opaque CertificateEntry extensions.

Therefore:

- `certificate_allows_delegation` is a prerequisite signal only.
- `credential_observed: false` is not proof that the peer lacks delegated
  credentials.
- An `observed` entry with an unsupported signature scheme still requires
  signature and certificate-key binding verification before it can be treated
  as trusted; a `verified` entry has passed the offline signature check.
- Full positive/negative wire validation requires a TLS backend that exposes
  CertificateEntry extensions and dedicated RFC 9345 fixtures.

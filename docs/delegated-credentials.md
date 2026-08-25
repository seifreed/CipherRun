# Delegated Credentials

CipherRun recognizes the RFC 9345 delegated-credentials contract without
claiming false wire-level support.

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
- Full positive/negative wire validation requires a TLS backend that exposes
  CertificateEntry extensions and dedicated RFC 9345 fixtures.

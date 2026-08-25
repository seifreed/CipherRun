# Client Compatibility Profiles

The bundled client database is exposed as a versioned compatibility contract
through `ClientDatabase::compatibility_profiles()`.

Each profile records:

- `schema_version`: currently `1.0`.
- `id`, `family`, `version`, `display_name`, and `lifecycle`.
- `simulation_backend`: currently `rustls`.
- `simulation_support`: `rustls` for TLS 1.2/1.3 profiles or `metadata_only`
  when the transport/protocol cannot be exercised by the runtime simulator.
- `limitations`: explicit reasons a profile is not byte-for-byte emulated.

The source file remains useful for historical ClientHello metadata, but its
captured bytes are not presented as a browser emulation guarantee. Profiles
whose highest protocol is TLS 1.0/1.1/SSLv3 and profiles requiring QUIC are
therefore classified as metadata-only. Updating
`data/client-simulation.txt` requires running the client-data tests and checking
the generated profile classifications before release.

# Validation coverage

CipherRun publishes executable evidence separately from detector implementation.
The controlled Docker lab currently proves the TLS negotiation boundary used by
configuration-inference checks. It does not turn a weak configuration into proof of
a historical implementation CVE.

Run `make lab-validate` to scan isolated `legacy-tls`, `legacy11-tls`, `weak-tls`, and `modern-tls` endpoints with
CipherRun, sslscan, testssl.sh, and OpenSSL. Raw output is written below
`results/differential/`; no fixture exposes a host port or reaches the public Internet.
Each run also publishes `fixture-metadata.json`, which records expected results,
false-positive/false-negative notes, and safety classification for every fixture.

| Check family | Method | Positive fixture | Negative fixture | Differential tools | Current limitation |
|---|---|---|---|---|---|
| TLS 1.0 / BEAST-era prerequisites | Configuration inference | `legacy-tls` | `modern-tls` | All four | Protocol posture only; no exploit claim |
| TLS 1.1 legacy negotiation | Configuration inference | `legacy11-tls` | `modern-tls` | All four | Protocol posture only; no exploit claim |
| TLS 1.2 CBC / Lucky13 prerequisites | Configuration inference | `weak-tls` | `modern-tls` | All four | Prerequisites only; no exploit claim |
| TLS 1.3 availability | Protocol negotiation | `modern-tls` | `weak-tls` | All four | Negotiation coverage only |
| QUIC listener discovery | UDP Version Negotiation probe | Explicit `--quic` target | Closed/filtered UDP port | CipherRun | Listener response only; does not claim HTTP/3 application support |
| HTTP/3 application support | `reqwest` HTTP/3 prior-knowledge request over QUIC | ALPN phase on a reachable HTTPS target | Closed/filtered UDP port | CipherRun | Requires a routable UDP path and returns inconclusive on transport loss |
| ECH | HTTPS/SVCB `ech` discovery plus rustls ECH TLS 1.3 handshake | Explicit `--ech` target publishing a compatible ECH config | No HTTPS/SVCB ECH config or rejected handshake | CipherRun | Requires DNS-published config and an ECH-capable endpoint; absent/rejected config is inconclusive |
| BEAST | Active/configuration probe | `legacy-tls-beast` | `modern-tls-beast` | CipherRun | TLS 1.0 CBC posture signal; no browser exploit claim |
| SWEET32 | Wire-level cipher probe | `sweet32-tls` | `modern-tls-sweet32` | CipherRun | Synthetic 3DES ServerHello; no birthday attack claim |
| FREAK, LOGJAM, RC4, NULL | Wire-level cipher probe | `weak-ciphers-tls` | `modern-tls-weak-ciphers` | CipherRun | Synthetic legacy ServerHello classification; no exploit claim |
| CRIME | Protocol negotiation | Not yet isolated | `modern-tls` | Not yet complete | Requires a controlled TLS compression configuration |
| Heartbleed, CCS Injection, Ticketbleed, ROBOT, POODLE variants, OpenSSL 0-Length, CVE-2016-2107 | Active probe | Not yet isolated | `modern-tls` | Not yet complete | Requires pinned vulnerable and patched implementations |
| BREACH | HTTP heuristic | `breach-tls` | `modern-tls` | CipherRun | Synthetic prerequisites only; no practical exploit demonstrated |
| Renegotiation, fallback SCSV, early data, GREASE | Negotiation/configuration | Partial | `modern-tls` | Not yet complete | Needs dedicated handshake fixtures |
| STARTTLS injection, Opossum | Active STARTTLS probe | Not yet isolated | Not yet isolated | Not yet complete | Needs protocol-specific mail fixtures |
| Winshock | Platform inference | N/A | N/A | N/A | Cannot be confirmed by a generic remote TLS endpoint |

The release criterion is intentionally not marked complete yet: every published probe
must gain a positive fixture, a negative fixture, an expected result, a captured
transcript, false-positive/false-negative notes, and a safety classification before
the matrix can claim full validation.

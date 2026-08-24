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
| Server interoperability | TLS 1.2/1.3 listeners behind nginx, Apache, HAProxy, Envoy, and Caddy | `*-interop` services in the isolated Compose lab | TLS 1.0/1.1 disabled on each service | CipherRun, sslscan, testssl.sh, OpenSSL | Listener posture only; application-specific behavior and load-balancer fleets require separate fixtures |
| STARTTLS negotiation interoperability | SMTP, IMAP, POP3, XMPP, PostgreSQL, MySQL, and LDAP capability/upgrade negotiation | `starttls-interop` | `starttls-negative` | CipherRun `--starttls-only`, OpenSSL transcripts | Negotiation boundary only; no TLS handshake, authentication, injection, Opossum, or historical CVE exploit claim |
| BEAST | Active/configuration probe | `legacy-tls-beast` | `modern-tls-beast` | CipherRun | TLS 1.0 CBC posture signal; no browser exploit claim |
| SWEET32 | Wire-level cipher probe | `sweet32-tls` | `modern-tls-sweet32` | CipherRun | Synthetic 3DES ServerHello; no birthday attack claim |
| FREAK, LOGJAM, RC4, NULL | Wire-level cipher probe | `weak-ciphers-tls` | `modern-tls-weak-ciphers` | CipherRun | Synthetic legacy ServerHello classification; no exploit claim |
| CRIME | TLS ServerHello compression negotiation | `crime-tls` | `crime-patched-tls` | CipherRun | Synthetic DEFLATE/null negotiation only; no secret-recovery attack claim |
| Heartbleed | Active heartbeat probe | `heartbleed-tls`; pinned OpenSSL 1.0.1c smoke via `make external-fixture` | `heartbleed-patched-tls`; pinned OpenSSL 1.1.1m TLS 1.2 control | CipherRun + OpenSSL client smoke | `docs/external-vulnerable-fixtures.json` records digests, expectations, safety, and transcript paths; the image pair proves legacy reachability and a patched control, while CipherRun confirmation remains a separate compatibility gate and is not inferred from version strings |
| CCS Injection | Active early-CCS probe | `ccs-tls` | `ccs-patched-tls` | CipherRun | Synthetic CCS transcript; no vulnerable OpenSSL implementation claim |
| Ticketbleed | Active session-ticket probe | `ticketbleed-tls` | `ticketbleed-patched-tls` | CipherRun | Synthetic session-ID transcript; no F5 BIG-IP implementation claim |
| ROBOT | Active RSA alert-oracle probe | `robot-tls` | `robot-patched-tls` | CipherRun | Synthetic RSA transcript; no vulnerable implementation or timing-oracle claim |
| POODLE classic (SSLv3) | Protocol negotiation | `poodle-tls`; pinned OpenSSL 1.0.1c SSLv3 fixture via `make external-fixture` | `poodle-patched-tls`; pinned OpenSSL 1.1.1m TLS 1.2 control | CipherRun + OpenSSL client smoke | SSLv3 prerequisite is now exercised against a pinned legacy implementation; no CBC padding oracle or browser exploit claim |
| POODLE variants, OpenSSL 0-Length, CVE-2016-2107 | Active probe | Pinned OpenSSL 1.0.1c multi-version CBC fixture covers 0-Length as `inconclusive` and CVE-2016-2107 as `inconclusive` | Pinned OpenSSL 1.1.1m GCM-only control | CipherRun + OpenSSL client smoke | 0-Length cannot be confirmed without observing memory disclosure; CVE-2016-2107 has no reliable remote timing signal; POODLE timing variants still require dedicated vulnerable implementations |
| BREACH | HTTP heuristic | `breach-tls` | `modern-tls` | CipherRun | Synthetic prerequisites only; no practical exploit demonstrated |
| Renegotiation, fallback SCSV, early data, GREASE | Negotiation/configuration | `renegotiation-insecure-tls`; `fallback-tls`; `early-data-tls`; `grease-intolerant-tls` | `renegotiation-secure-tls`; `fallback-patched-tls`; `early-data-patched-tls`; `grease-tolerant-tls` | CipherRun | Renegotiation now has an isolated RFC 5746/incomplete-handshake pair; the insecure candidate is intentionally inconclusive because remote proof of CVE-2009-3555 requires completing renegotiation |
| STARTTLS injection | Active STARTTLS command-pipelining probe | `smtp-injection`, `imap-injection`, `pop3-injection` | `*-injection-patched` | CipherRun | Synthetic transcripts validate the heuristic; no authentication or proxy deployment claim |
| Opossum (CVE-2022-0778) | Certificate parsing / timeout probe | Not yet isolated | `modern-tls` | Not yet complete | Requires pinned vulnerable and patched certificate parsers |
| Winshock | Platform inference | N/A | N/A | N/A | Cannot be confirmed by a generic remote TLS endpoint |

The release criterion is intentionally not marked complete yet: every published probe
must gain a positive fixture, a negative fixture, an expected result, a captured
transcript, false-positive/false-negative notes, and a safety classification before
the matrix can claim full validation.

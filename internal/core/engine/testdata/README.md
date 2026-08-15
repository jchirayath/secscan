# Golden fixtures

Real output captured from live runs of `testssl.sh` and `nuclei`, with
hostnames and addresses replaced by documentation-reserved equivalents
(`example.net`, TEST-NET-2 `198.51.100.10`).

The substitution is deliberate and costs nothing: these fixtures exist to pin
the *shape* of another program's output, and a shape does not depend on whose
host it came from. Committing the original names would have published the
layout of a live estate — which services exist, which are behind an identity
provider, what the reverse DNS says — in the test data of a security scanner,
for no testing benefit whatsoever.

If you capture new fixtures, sanitise them the same way.

## `testssl-clientproblem.json`

Captured after fixing the invocation to write JSON to a temp file instead of
`/dev/stdout`. It carries `clientProblem1` (a complaint about the *scanner's*
own openssl) alongside a full `scanResult`, which is the combination that
exposed two separate faults:

1. On `/dev/stdout` the document was interleaved with testssl's ANSI-coloured
   console output — `--quiet` suppresses the banner, not the running commentary
   — so the parse died on the first escape byte and TLS coverage was lost.
2. A `clientProblem`-only document parsed cleanly to zero findings and was
   reported as "the target may not have completed a TLS handshake", pointing the
   operator at the wrong machine entirely.

Keep this fixture free of escape bytes; an ANSI sequence in it means it was
captured from a polluted stream and pins the wrong shape.

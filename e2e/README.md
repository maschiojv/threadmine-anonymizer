# e2e parity harness

Proves the central promise of `tm-anon`: **same detections, same score** — a
masked dump analyzed by ThreadMine must yield the same problems and the same
health score as the original dump.

The harness is a standalone single-file Java program ([`parity.java`](parity.java)).
It lives outside the Maven build on purpose: the project ships a no-network
architecture test that keeps `src/` (and the jar) free of any network code.
`java.net.http` is used only here, in a file that is never compiled into the
artifact.

## What it does

For every fixture in `corpus/fixtures/` (plus any extra dump passed as an
argument):

1. `tm-anon mask` with a throwaway vault (`e2e/out/vault.json`, git-ignored) and
   `tm-anon verify` original vs masked;
2. uploads the ORIGINAL and the MASKED dump as two separate analyses through
   the ThreadMine capture API (`POST /api/v1/analises/captura`, Bearer API key,
   429-aware with `Retry-After`);
3. polls `GET /api/v1/analises/{id}` until `CONCLUIDA`, then downloads the JSON
   export of both;
4. compares: problem multiset (type / severity / affected-thread count), health
   score, total threads, detected format. Verdict per fixture:
   - `IGUAL` — bit-identical facts;
   - `DESVIO_ESPERADO` — divergence covered by the documented expected
     deviations (AVALIACAO §1.2 item 9: (a) package-less fragment matches such
     as `Consumer.receive` stop matching after tokenization; (b) scheduler pools
     with custom prefixes fall back to stack-based detection);
   - `DESVIO_INESPERADO` — anything else (a real finding);
5. round-trip: `tm-anon unmask` on the masked analysis export and checks that
   the thread-name set equals the original analysis export exactly.

Artifacts land in `e2e/out/<fixture>/` (masked dump, both detail JSONs, both
exports, unmasked export) and the matrix in `e2e/out/matrix.md`.

## Prerequisites

- JDK 21+ (`java` on PATH); jbang works too but is not required.
- The fat jar: `./mvnw -DskipTests package` → `target/tm-anon-0.3.0-SNAPSHOT.jar`.
- A running ThreadMine backend and an API key (`tf_...`).

## Run

```bash
# offline unit tests of the comparison logic (no backend needed)
java e2e/parity.java self-test

# full sweep
TM_API_KEY=tf_... java e2e/parity.java run \
    [--base-url http://localhost:8090] \
    [--jar target/tm-anon-0.3.0-SNAPSHOT.jar] \
    [--fixtures corpus/fixtures] [--out e2e/out] \
    [extra-dump.txt ...]
```

Exit codes: `0` all fixtures IGUAL/DESVIO_ESPERADO and round-trips OK; `1`
usage; `2` at least one DESVIO_INESPERADO, round-trip failure or infra error.

The harness paces uploads (~3.5 s apart) to stay under the capture API rate
limit (20 req/min per key). A full 17-fixture sweep takes a few minutes.

Results of the reference run: [`PARITY_REPORT.md`](PARITY_REPORT.md).

# Parity report — original vs masked on ThreadMine

**Claim under test:** *same detections, same score* — a dump masked by `tm-anon`
must produce the same detected problems and the same health score as the
original dump when analyzed by ThreadMine (SPEC §9, definition of done, item 2).

- Date: 2026-07-29
- Backend: ThreadMine dev, `http://localhost:8090` (capture API, Bearer `tf_` key,
  disposable FREE-plan workspace)
- Anonymizer: `feat-e2e-parity` branch, fat jar `tm-anon-0.1.0-SNAPSHOT.jar`
  built from commit `17619ec` (wave 2E+2F merged)
- Harness: [`e2e/parity.java`](parity.java) (see [`e2e/README.md`](README.md)
  for reproduction); one throwaway vault shared by the whole sweep, which also
  exercises inter-dump token determinism
- Corpus: all 17 fixtures in `corpus/fixtures/`

## Result matrix

Problem notation: `TYPE:SEVERITY:affected-thread-count`. Round-trip = `tm-anon
unmask` on the masked analysis' JSON export, thread-name set compared against
the original analysis' export.

| Fixture | Health orig | Health masked | Problems orig | Problems masked | Verdict | Round-trip |
|---|---|---|---|---|---|---|
| deadlock-single-cycle | 39 | 39 | DEADLOCK:CRITICAL:2 | DEADLOCK:CRITICAL:2 | IGUAL | OK (9 names) |
| deadlock-two-cycles | 39 | 39 | DEADLOCK:CRITICAL:2 (x2 blocks) | DEADLOCK:CRITICAL:2 (x2 blocks) | IGUAL | OK (8 names) |
| edge-inverted-order | 100 | 100 | (none) | (none) | IGUAL | OK (4 names) |
| edge-lambda-inner-cglib * | 95 | 95 | CPU_BOUND:WARNING:3 | CPU_BOUND:WARNING:3 | IGUAL * | OK (4 names) |
| edge-no-header | 60 | 60 | (none) | (none) | IGUAL | OK (3 names) |
| edge-pool-starvation | 55 | 55 | LOCK_CONTENTION:WARNING:8, THREAD_STARVATION:CRITICAL:8 | LOCK_CONTENTION:WARNING:8, THREAD_STARVATION:CRITICAL:8 | IGUAL | OK (14 names) |
| edge-relock-compiling | 94 | 94 | CPU_BOUND:INFO:2 | CPU_BOUND:INFO:2 | IGUAL | OK (10 names) |
| edge-thread-names-route-uuid | 100 | 100 | CPU_BOUND:INFO:1 | CPU_BOUND:INFO:1 | IGUAL | OK (7 names) |
| jcmd-dump-text | 90 | 90 | (none) | (none) | IGUAL | OK (6 names) |
| jcmd-thread-print | 100 | 100 | CPU_BOUND:INFO:1 | CPU_BOUND:INFO:1 | IGUAL | OK (8 names) |
| jstack-jdk11-smr | 100 | 100 | (none) | (none) | IGUAL | OK (16 names) |
| jstack-jdk17-synchronizers | 100 | 100 | (none) | (none) | IGUAL | OK (14 names) |
| jstack-jdk21-virtual-threads | 85 | 85 | CPU_BOUND:WARNING:4, VIRTUAL_THREAD_PINNED:WARNING:1 | CPU_BOUND:WARNING:4, VIRTUAL_THREAD_PINNED:WARNING:1 | IGUAL | OK (8 names) |
| jstack-jdk25-full | 100 | 100 | CPU_BOUND:INFO:1 | CPU_BOUND:INFO:1 | IGUAL | OK (20 names) |
| jstack-jdk8-classic | 55 | 55 | CPU_BOUND:INFO:1, POOL_EXAURIDO:CRITICAL:2, REQUISICAO_PRESA:CRITICAL:1 | CPU_BOUND:INFO:1, POOL_EXAURIDO:CRITICAL:2, REQUISICAO_PRESA:CRITICAL:1 | IGUAL | OK (15 names) |
| multi-dump-3x | 90 | 90 | (none) | (none) | IGUAL | OK (4 names) |
| mxbean-visualvm | 92 | 92 | (none) | (none) | IGUAL | OK (7 names) |

**Score: 17/17 fixtures with identical health score, identical problem set
(type, severity and affected-thread count) and lossless unmask round-trip.**
Zero DESVIO_ESPERADO used, zero DESVIO_INESPERADO in the analysis results.
Detected format also matched on every pair (the `# tm-anon v1` header line does
not disturb format detection).

\* `edge-lambda-inner-cglib` was measured manually because the harness aborts a
fixture when `tm-anon verify` fails, and verify false-positives on this fixture
(bug below — a *verify* bug, not a parity deviation). The mask output itself is
correct and the ThreadMine results are identical.

## Round-trip detail (item 3 of SPEC §9)

Beyond thread-name set equality on all 17 fixtures, spot checks on the unmasked
masked-analysis export:

- `edge-lambda-inner-cglib`: full `stackFrames` array of `order-async-1` equals
  the original export byte for byte (e.g.
  `com.acme.order.OrderService.lambda$processOrder$0(OrderService.java:67)`).
- `edge-pool-starvation`: token embedded in **prose** restored — root-cause
  description `Pool "pgto-worker" em starvation ...` identical to the original
  export; zero token-shaped residues (`[a-z]hex5xhex5`) anywhere in the
  unmasked JSON.

## Findings

### BUG (verify, false positive): CGLIB scaffolding and `(<generated>)` flagged as residual identifiers

- **Where:** `src/main/java/dev/threadmine/anon/verify/ComplianceVerifier.java`
- **What:** on a correctly masked frame such as
  `at p...x....C00d1fx4700a$$FastClassBySpringCGLIB$$1a2b3c4d.m66fcbx0fda2(<generated>)`
  verify reports 4 residual identifiers (2x FRAME_CLASS + 2x SOURCE_FILE) and
  exits 4, even though the mask followed SPEC §5.2 (generated-class scaffolding
  verbatim, only base class and method tokenized — exactly what the corpus
  expectation for this fixture demands).
- **Root cause:** `isMaskedIdentifier` splits atoms on `[.$]`, and `atomIsSafe`
  has no case for CGLIB scaffolding: `FastClassBySpringCGLIB` /
  `EnhancerBySpringCGLIB` are not in `STRUCTURAL_ATOMS`, and the bare-hex hash
  (`1a2b3c4d`) matches neither `DIGITS` (decimal only) nor `HEX_ADDRESS`
  (requires `0x`). Independently, `NON_LOCATIONS` lacks `<generated>`, so the
  source-file check also fires.
- **Minimal repro pair:** `corpus/fixtures/edge-lambda-inner-cglib.txt` +
  its mask output (any vault):
  `java -jar target/tm-anon-*.jar mask corpus/fixtures/edge-lambda-inner-cglib.txt -o m.txt --vault v.json`
  then `verify` the pair -> exit 4 with the 4 findings above. A single-line dump
  containing `at com.acme.Foo$$FastClassBySpringCGLIB$$1a2b3c4d.invoke(<generated>)`
  reproduces it too.
- **Classification:** verify bug (fail-closed false positive). Not a mask bug,
  not an analysis-parity deviation. Impact: users masking Spring/CGLIB-heavy
  dumps get a spurious "not safe to upload" and exit code 4.
- **Not fixed here** (out of this task's scope, per instructions). Suggested
  fix direction: treat `$$<KnownScaffold>$$<hex>` segments as structural in
  `atomIsSafe` (mirroring the rewriter's own scaffolding rules) and add
  `<generated>` to `NON_LOCATIONS`.

### Notes (not bugs)

- **Vein/IA:** the test workspace is FREE plan, `forgeAiStatus=BLOQUEADO` on
  every analysis. The deterministic pipeline (parser, detectors, health score,
  export) is what parity covers here; Vein parity was not exercised. This does
  not invalidate the deterministic parity result.
- The expected-deviation rules of AVALIACAO §1.2 item 9 (consumer-idle
  fragment matches, scheduler custom-prefix fallback) are implemented in the
  harness classifier but **no fixture needed them** — the corpus does not
  currently contain a dump that triggers those detectors via package-less
  fragments. If such a fixture is added (e.g. an app frame containing
  `Consumer.receive`), the harness will classify the divergence automatically.
- Uploads are paced (~3.5 s) for the capture API rate limit (20 req/min/key);
  a full sweep is ~35 uploads and ran without hitting the FREE daily quota.

## Verdict on SPEC §9 (definition of done, MVP 0)

| Item | Status |
|---|---|
| (1) mask output passes `verify` | **16/17 fixtures** — fails only on `edge-lambda-inner-cglib` due to the verify false positive above (the masked file itself contains no residual identifiers; confirmed manually) |
| (2) accepted by ThreadMine dev with the SAME problems and health score | **PASS — 17/17 fixtures**, automated by this harness |
| (3) `unmask` of the export JSON restores real names, including inside prose | **PASS — 17/17 fixtures** + prose spot checks |
| Zero network code in the jar | **PASS** — `./mvnw test` (incl. `NoNetworkArchitectureTest`) green; the harness lives outside the Maven build |

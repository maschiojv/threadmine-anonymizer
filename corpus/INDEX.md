# Golden corpus — tm-anon

Fully synthetic dumps (fictional `com.acme.*` namespace, fictional threads, zero real data),
shaped after the real ThreadMine fixtures (`backend/src/test/resources/dumps/`). Every
`fixtures/<name>.txt` has an `expectations/<name>.yaml` (SPEC §6 schema) stating what a correct
`mask` MUST do. Global rules, true for all of them: first line of the output is `# tm-anon v1`;
an unclassified line becomes `# [tm-anon: redacted]`; `<0x…>` addresses are always verbatim.

**26 fixtures**: 23 HotSpot-family ones, green in two independent tests — `CorpusGoldenTest` (mask
does what the expectation says) and `CorpusMaskVerifyTest` (mask output passes `verify`, with the
same allowlist on both sides, which is how the JDK 24+ `<FQCN@hash>` leak was caught) — and 3
OpenJ9 javacores (`format: openj9-javacore`, SPEC §5-B contract), consumed by `JavacoreRewriter`
and running through both tests as well.

`invariants` vocabulary: `intra_dump_determinism`, `inter_dump_determinism`,
`deadlock_names_consistent`, `blank_lines_preserved`, `lock_addresses_verbatim`,
`numeric_suffix_preserved`, `route_marker_q`, `line_order_preserved`,
`accepts_without_full_thread_dump_header`; javacore (§5-B): `native_ids_verbatim`,
`threadinfo_stacktrace_order_preserved`, `slash_frames_tokenized`, `blocked_on_consistent`,
`verify_exit4_if_forbidden_section_survives`, `verify_exit4_if_1tifilename_has_content`. Javacore
expectations carry extra fields: `detection_anchors_4kb`, `preserved_sections`,
`stripped_sections`, `redacted_lines`.

| Fixture | What it exercises | Design trap it covers |
|---|---|---|
| `jstack-jdk8-classic.txt` | jstack JDK 8: no cpu=/elapsed=, frames without a module, singular `JNI global references:`, Heap section (kill -3), Tomcat/http-nio | the lexer cannot assume post-JDK9 fields or module prefixes; stripping the multi-line Heap section |
| `jstack-jdk11-smr.txt` | JDK 11: SMR block, cpu=/elapsed=, `java.base@11.0.16/`, G1 tail, `Thread-7`, custom pool with a suffix | stripping the SMR block without breaking blank lines; two VM threads with no blank line between them |
| `jstack-jdk17-synchronizers.txt` | JDK 17 `-l`: `Locked ownable synchronizers` on every thread, ReentrantLock held×parked | stripping the block without swallowing the delimiting blank line; held/waiter correlation through the verbatim address |
| `jstack-jdk21-virtual-threads.txt` | Loom: anonymous mounted VT, `<pinned: synchronized>` VT, VT with no carrier, named VT, FJP carriers | Loom markers byte for byte; `"" #N virtual` has nothing to tokenize; the carrier named in the marker is allowlisted |
| `jstack-jdk25-full.txt` | JDK 25: `#N [nid]`, allocated=/defined_classes=, decimal nid, `No compile task`, VirtualThread-unblocker, delayScheduler, process reaper, GC tail | rewriting the name must not touch the new header fields; infrastructure threads with no stack and no state |
| `jcmd-thread-print.txt` | `jcmd <pid> Thread.print`: `48350:` preamble plus a body identical to jstack | the jcmd preamble must not be redacted by fail-closed, nor confuse detection inside the first 4KB |
| `jcmd-dump-text.txt` | `Thread.dump_to_file -format=text`: `#N "name" STATE`, 6-space frames with `java.base/`, `#N "" VIRTUAL` | frames without `at ` and without the module `@` parenthesis; same canonical names imply the same tokens as the other dialects |
| `jcmd-dump-text-jdk21.txt` | the **real** JDK 21-23 dialect: `#N "name"` **with no state**, lowercase `virtual` as a suffix, 6-space frames, not a single `java.lang.Thread.State:` line in the whole file | a stateless header used to be `redacted` and the file was refused by `FormatDetector` (no other detection rule catches this dialect) |
| `jcmd-dump-text-jdk25.txt` | the **real** JDK 24+ dialect: `#N "name" [virtual ]STATE <Instant>`, `    at ` frames, monitors as `<FQCN@identityHash>`, `, owner #N`, `- lock is eliminated` | what sits between `<>` stops being an address and starts carrying **the application class name**, so keeping it verbatim (correct for an address) was a leak |
| `jstack-jdk25-carrying.txt` | mounted carrier: `Carrying virtual thread #N` **replacing** the `java.lang.Thread.State:` line; mounted VT with a Loom marker; `#N [nid]` header | a thread block with no state line must not break the lexer; the number after `#` is a threadId, not a name, so it stays verbatim |
| `mxbean-visualvm.txt` | ThreadMXBean/VisualVM: `"name" Id=N STATE on Class@hash owned by "other" Id=M`, `app//`, `Number of locked synchronizers` | the name quoted in `owned by` gets the SAME token as the header; `Class@hash` becomes a tokenized class with the @hash verbatim |
| `deadlock-single-cycle.txt` | one-cycle deadlock: full `Found one Java-level deadlock:` block plus `===`, `Java stack information` and `Found 1 deadlock.` | quoted names inside the block are the header tokens (SPEC §5.5); the class in `(object 0x…, a X)` is tokenized inside its moulding |
| `deadlock-two-cycles.txt` | two simultaneous cycles: two blocks plus the plural `Found 2 deadlocks.` | assignments must not bleed across blocks; `billing-sched-1` and `report-render-1` share a suffix but get distinct tokens |
| `multi-dump-3x.txt` | three concatenated jstacks, same threads changing state | inter-dump determinism: the token has to be stable across the three dumps or the server's timeline and correlation die |
| `edge-inverted-order.txt` | file with its lines in reverse order (header on the last line) | classification by line shape, not by position; the output must not be reordered |
| `edge-no-header.txt` | no `Full thread dump`, minimal headers (`#N prio= tid= nid=`) | the header anchor is sufficient but NOT necessary; refusing would block an upload ThreadMine accepts |
| `edge-lambda-inner-cglib.txt` | `$$Lambda$123/0x…` (JDK 15-20) and `$$Lambda/0x…` (21+), `Foo$Bar`/`$1`, `lambda$met$0`, CGLIB `$$EnhancerBySpringCGLIB$$hash` plus `(<generated>)`, `<init>`/`<clinit>`, LambdaForm | generated-class mouldings stay intact and only the base class and method are tokenized (SPEC §5.2); spring is recommended tier |
| `edge-thread-names-route-uuid.txt` | threads named after a route with a query string (`sync-/api/orders?id=…`), UUID, hex≥16 plus spaces, `#4` suffix, `Thread-7` | the route heuristic runs BEFORE the suffix rule (a UUID must not be sliced); single `t…/q` token; the allowlist beats the heuristic |
| `edge-pool-starvation.txt` | real starvation: `pgto-worker-1..8` all BLOCKED on the same monitor, the owner in IO; idle http-nio threads for contrast | a shared prefix means the same base token plus suffixes, which is what preserves pool grouping and starvation detection on the server |
| `edge-relock-compiling.txt` | `waiting to re-lock in wait()`, `<no object reference available>`, `Compiling: com.acme…` (with and without `%` OSR), `process reaper (pid 4242)`, `gc-notifier-1` | Compiling is stripped (it leaks FQCN::method outside the frame format); the sentinel stays verbatim; lowercase `gc-` is not the `GC ` infrastructure prefix |
| `openj9-javacore-classic.txt` | classic IBM javacore (J2RE 1.4.2, like ThreadMine's real one): no `1XMJAVAVERSION`, `state:R/CW/B` threads carrying `TID/sys_thread_t/native ID` on the line, `1TIFILENAME` with a local path, `1CICMDLINE` with `-D` password/host, a huge `1CISYSCP`, LK with `class@address` monitors plus thread names, CL with classloaders and classes | the whole monster surface of AVALIACAO §3 in one file: section stripping (CI/DC/DG/ST/XE/LK/CL plus XHPI/End through fail-closed §5-B.6); `1TISIGINFO` is the ONLY anchor in the first 4KB; the classic pool form `X: 'N' for queue: 'Q'` has no `-N` suffix, so it yields one token per thread (pool grouping is lost, a limitation recorded on purpose); a thread with no stack must not break the lexer |
| `openj9-javacore-modern.txt` | OpenJ9 0.41 in a container: `ENVINFO/LOCKS/THREADS/CLASSES` sections (same CI/LK/XM/CL families), `1XMJAVAVERSION`, `3XMTHREADINFO3 Java.lang.Thread.State:`, `3XMTHREADBLOCK Blocked on: … Owned by: "…"`, frames with **slashes** plus `(Compiled Code)`, `pgto-worker-N` pool, route thread with `?` and spaces, `2CIENVVAR` with `HOSTNAME`/password, `Anonymous native thread`, `4XENATIVESTACK` | modern section names differ from classic ones, so sections are identified by token family and never by the `0SECTION` text; `com/acme/...` must normalize to the SAME token as the dotted canonical form (and `java/util/...` stays allowlisted); the name quoted in `Owned by:` is the header token; lines no rule covers (native ones) fall into fail-closed without taking the file down |
| `openj9-javacore-deadlock.txt` | OpenJ9 deadlock: `1LKDEADLOCK`/`2LKDEADLOCKTHR`/`4LKDEADLOCKOBJ` plus monitors with `3LKWAITERQ/3LKWAITER` inside LOCKS, and the two `state:B` threads cross-referenced by `3XMTHREADBLOCK` in THREADS | stripping LOCKS wholesale (§5-B.2) erases the explicit "Deadlock detected !!!" announcement; the surviving evidence is the closed cycle of `3XMTHREADBLOCK` lines, which MUST stay closed after masking (same thread and class tokens on both sides); `verify` exits 4 if any `*LKDEADLOCK*` line survives |
| `zing-c4-jstack.txt` | Azul Zing (Prime): `Full thread dump Zing (…)` banner, `Zing thread dump header:` block with metadata, C4 collector threads | the banner is the format detection anchor, so rewriting it would classify the dump as another dialect; the metadata block is read by no analyzer and used to fall entirely into fail-closed (now stripped); `C4 …` threads were already allowlisted by the GC regex |
| `graalvm-native-image.txt` | GraalVM Native Image: state **inline** in the header, decimal `tid=`, no `java.lang.Thread.State:` line, `Heap: { … }` and `Isolates: { … }` blocks delimited by braces | `Isolates` is the ONLY place in the **text** corpus where an application class shows up outside a frame (`Object at 0x…: com.acme.boot.ServiceRegistry`); §5.7 says strip the section, and brace delimiting (rather than indentation) means counting depth, otherwise the closing `}` leaks as an unclassified line |
| `jcmd-dump-json-jdk25.txt` | `jcmd Thread.dump_to_file -format=json` (JDK 21+), **derived from a real capture** of a JDK 25 process (platform pool, virtual threads, contended lock, route thread): `threadContainers` with `parent`/`owner`, `parkBlocker` as an OBJECT, `monitorsOwned[].locks[]`, numeric `depth`, boolean `virtual` | `container` carries the `toString()` of the executor or StructuredTaskScope, the application class naming itself outside any frame; `parent` refers to another container by its exact string, so the link dangles unless both are rewritten identically; the §5.9 marker **cannot** be a leading `#` line without invalidating the JSON, so it goes in as the first key; an unknown key from a future JDK is redacted, not passed through |

## Gaps — status

- ~~**The `Carrying virtual thread #N` line**~~ **CLOSED** — `jstack-jdk25-carrying.txt`, with two
  occurrences pinned as anchors. Decision (SPEC §5.6, not §5.7): **keep it byte for byte.** The
  `#N` is the threadId of the mounted VT, not a name, so there is nothing to tokenize, and the
  line is read by ThreadMine's HotSpot parser and listed as a `structuralMarker` in allowlist v1.
  Real-format detail the fixture records: the line **replaces** the carrier's
  `java.lang.Thread.State:` (HotSpot prints one or the other), so a legitimate thread block with
  no state line does exist.
- ~~**Containers in `Thread.dump_to_file -format=text`**~~ **WRONG PREMISE — they do not exist.**
  Checked against the OpenJDK source (`jdk/internal/vm/ThreadDumper.java`, tags `jdk-21+35` and
  `master`): the text walker is
  `container.threads().forEach(...); container.children().forEach(...)`, so it **walks** the
  containers but **prints** no container line at all. `<root>` and
  `java.util.concurrent.ThreadPerTaskExecutor@…` only show up in `-format=json`. Nothing to
  implement; a container fixture would be fiction. What the text dialect really did have
  uncovered became `jcmd-dump-text-jdk21.txt` and `jcmd-dump-text-jdk25.txt`.
- ~~**Non-HotSpot dialects**~~ **CLOSED.** OpenJ9 javacore: three `openj9-javacore-*` fixtures.
  **Zing and GraalVM:** `zing-c4-jstack.txt` and `graalvm-native-image.txt`. Both bodies are
  HotSpot-shaped (Zing derives from HotSpot and its `jstack` prints the same layout), so they
  already went through the HotSpot rewriter; what was missing were the sections: GraalVM-style
  `Heap: { }` / `Isolates: { }` blocks (delimited by braces, not indentation) and the Zing
  metadata header. That was 16 lines landing in `redacted`: safe, but it handed the user 16
  "I did not recognize this line" warnings on a perfectly ordinary dump, which corrodes trust in
  the warning for the times it matters. They are `stripped` now, with 0 redactions in both
  fixtures.
- **GraalVM Native Image, minimal header with no `#N`/`prio=`:** the format admits, in theory, a
  `"name" tid=1 nid=0x1 runnable` header with every optional field absent, which the rewriter's
  `QUOTED_HEADER` does not match (fail-closed, so the whole thread becomes `redacted`). Not
  reproduced in a real dump and not covered by a fixture: recorded here instead of "fixed" on a
  guess.
- **Javacore format notes (decisions taken while building the corpus):**
  1. **`1XMJAVAVERSION` and `3XMTHREADINFO3 Java.lang.Thread.State:` belong to ThreadMine's
     PARSER dialect, not to real OpenJ9.** A genuine javacore carries the version in
     `1CIJAVAVERSION` (the ENVINFO/CI section, which §5-B says to strip) and uses
     `3XMTHREADINFO3` as the `Java callstack:` header; the real state lives in the `state:X` of
     `3XMTHREADINFO` itself. The modern fixtures include both parser tokens (the golden set
     serves parity with ThreadMine), but mask has to accept javacores WITHOUT them.
     **Amendment IMPLEMENTED (fix-javacore-version):** when stripping CI/ENVINFO, the
     `1CIJAVAVERSION` payload is re-emitted exactly once right after the strip marker, under the
     `1XMJAVAVERSION` token (the only one the OpenJ9 parser reads; re-emitting the `1CI` token
     would be flagged by `verify` as a surviving forbidden section). The payload is verbatim
     behind a per-word fail-closed filter: version vocabulary passes, anything shaped like a
     path, an env var or a hostname becomes `[tm-anon:redacted]` (with no digits, so it can never
     be read as a version) plus a warning. No re-emission when the dump already has
     `1XMJAVAVERSION`.
  2. **`0SECTION` names change between generations** (classic: `CI/LK/XM/CL`; modern:
     `ENVINFO/LOCKS/THREADS/CLASSES`). §5-B names sections by token family, and identification
     MUST follow the family (the alphabetic prefix of the column-0 token), never the `0SECTION`
     text, otherwise fail-closed §5-B.6 strips the entire THREADS section of a modern javacore.
  3. **Modern frames use slashes** (`com/acme/...`) and allow `(Compiled Code)` inside the
     parenthesis, as in `(File.java:NN(Compiled Code))`. §5.1, written for dotted FQCNs, needs
     slash-to-dot normalization before the allowlist and canonical lookup, including in order to
     RECOGNIZE `java/util/...` as allowlisted. In the **classic** dialect the same moulding comes
     WITHOUT a line number (`(File.java(Compiled Code))`): mask tokenizes the file and preserves
     the moulding, and `verify` has to cut it off before demanding a token for the file name.
     Without that, a well-masked real javacore comes out with exit 4 (a false positive, same
     family as CGLIB's `(<generated>)`). Pinned by the classic fixture's
     `compiled_code_moulding_preserved` invariant.
  4. **Stripping LOCKS erases the explicit deadlock declaration** (`1LKDEADLOCK`). §5-B accepts
     the cost (the OpenJ9 parser ignores LK); detection survives through the crossed
     `3XMTHREADBLOCK` lines, pinned by the deadlock fixture.
  5. Lines with no rule inside XM/THREADS (`Anonymous native thread` without quotes,
     `4XENATIVESTACK`, `3XMJAVALTHREAD`/`3XMTHREADINFO1`/`3XMCPUTIME`): the last three are
     neutral metadata and could be preserved, but §5-B does not mention them. The expectations
     treat only the first two as fail-closed and leave the rest as a decision (preserving is
     safe, since they carry no application identifier).
  6. **Allowlist v2 (OpenJ9 candidates):** `JIT Compilation Thread-`, `IProfiler`,
     `Attach API wait loop`, and a structural marker for `Anonymous native thread`. Today the
     expectations declare those names as tokenized, since allowlist-v1 does not cover them.
- ~~**JSON format** of `Thread.dump_to_file -format=json`~~ **CLOSED.** The predicted leak was
  real: `threadContainers[].container` prints the `toString()` of the executor or
  `StructuredTaskScope` that owns the group (`com.acme.batch.LedgerScope@4f2b1a`), the
  application class naming itself outside any frame, and `blockedOn`/`waitingOn`/
  `parkBlocker.object`/`monitorsOwned[].locks[]` repeat the shape. Before that, mask **refused**
  the file (exit 2: correctly fail-closed, but whoever had the dump was left with nothing). Now:
  the `jcmd-dump-json-jdk25.txt` fixture (a real JDK 25 capture), `format.json.JsonThreadDumpRewriter`
  (the document is parsed and walked, unknown key redacted) and a JSON path in `verify`.
  Deliberate deviation: the marker goes in as the first **key** (`"tmAnon"`) rather than a
  leading `#` line, which would invalidate the JSON.
- **`jcmd-dump-text.txt` (the original fixture) uses a synthetic shape**: `#N "name" VIRTUAL STATE`,
  with `VIRTUAL` uppercase and before the state. The real JDK never printed it that way (21-23:
  no state, ` virtual` suffix; 24+: lowercase `virtual ` plus state plus `Instant`). Kept as is,
  since mask accepts all three shapes and ThreadMine's regex (`THREAD_HEADER_JCMD`) matches this
  one, but anyone using it as a format reference should prefer the two newer fixtures.
- Expectations cite allowlist entries by expected behaviour (http-nio, FJP, Thread-N,
  process reaper…); the source of truth is the allowlist artifact itself. If allowlist-v1
  diverges, adjust the YAMLs, not the other way around.

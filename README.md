# threadmine-anonymizer (`tm-anon`)

Anonymize a JVM thread dump **on your own machine**, before it goes anywhere.

`tm-anon` replaces your application's package, class, method and thread names
with deterministic pseudonyms, keeps everything an analyzer needs to work
(structure, JDK/framework frames, lock addresses, states, pool suffixes), and
stores the reverse mapping in a local vault file. You can then upload the masked
dump to an analysis service such as [ThreadMine](https://threadmine.dev), and
run the analysis output back through `tm-anon unmask` to read it with your real
names again.

The jar contains **zero network code**. Not "we promise we don't upload
anything" — there is no HTTP client and no `java.net` usage in it at all, and a
test in this repo proves it. See [Why you can trust this](#why-you-can-trust-this).

- License: [MIT](LICENSE) · Requires: **Java 21+** · Runtime dependencies: **none**
- Threat model and honest limits: [THREAT_MODEL.md](THREAT_MODEL.md)

---

## The problem

Thread dumps are the fastest way to find out why a JVM is stuck. They are also
full of your internal names: `com.acme.payment.LedgerService`, thread names that
carry tenant ids, routes, or customer identifiers. In a lot of companies that is
exactly why nobody is allowed to paste a dump into a third-party analyzer.
Security says no, and security is right.

`tm-anon` makes the dump boring before it leaves the machine:

```
jstack <pid> > dump.txt
tm-anon mask dump.txt                    # -> dump.anon.txt (no internal names left)
tm-anon verify dump.txt dump.anon.txt    # compliance gate: must PASS
                                         # upload dump.anon.txt, get the analysis back
tm-anon unmask export.json               # your real names, back on your machine
```

The masked dump is still analyzable: the same detections fire and the same
health score comes out, because everything the detectors match by name is on a
published, auditable [allowlist](allowlist/allowlist-v1.json) and stays verbatim
(JDK internals, `http-nio-8080-exec-1`, `ForkJoinPool-1-worker-3`,
Tomcat/Netty/Kafka frames, GC threads), while everything that is yours becomes a
token.

## Install and run

**Requires a JDK 21 or newer.** Pick one:

```bash
# 1. jar (primary artifact)
curl -LO https://github.com/maschiojv/threadmine-anonymizer/releases/latest/download/tm-anon.jar
java -jar tm-anon.jar

# 2. jbang (nothing to install beyond a JDK)
jbang catalog add --name=threadmine https://github.com/maschiojv/threadmine-anonymizer/blob/master/jbang-catalog.json
jbang tm-anon@threadmine mask dump.txt

# 3. native binary, no JVM needed to run it: tm-anon-linux-amd64,
#    tm-anon-macos-arm64, tm-anon-windows-amd64.exe — attached to each release

# 4. from source
./mvnw package        # -> target/tm-anon-<version>.jar
```

A shell alias makes the rest of this README copy-pasteable:

```bash
alias tm-anon='java -jar /path/to/tm-anon.jar'
```

## Quickstart

Everything below is real output, produced by running the jar against
[`corpus/fixtures/jstack-jdk17-synchronizers.txt`](corpus/fixtures/jstack-jdk17-synchronizers.txt)
(copied to `payments-prod.txt`). Nothing here is illustrative fiction.

### 1. Create the vault (once per project)

```
$ tm-anon init
Created vault: /home/you/work/tm-anon-vault.json

Back this file up. It holds the HMAC key and the token dictionary:
  - lose it and you can never unmask an already masked dump;
  - share it and anyone can unmask those dumps.
Never commit it, never upload it, never attach it to a ticket.
```

When the working directory is a git repository, `init` also adds the vault to
`.gitignore`.

### 2. Mask the dump

```
$ tm-anon mask payments-prod.txt
masked  payments-prod.txt -> payments-prod.anon.txt
lines:  78 preserved, 10 tokenized, 22 stripped, 0 redacted
Reminder: upload the masked file under a neutral file name and title -
the original name often carries the very identifiers you just masked.
```

Before:

```
"pgto-worker-1" #15 prio=5 os_prio=31 cpu=4211.03ms elapsed=410.55s tid=0x00007fb2a3813200 nid=0x5203 runnable  [0x000000016d0be000]
   java.lang.Thread.State: RUNNABLE
	at java.net.SocketInputStream.socketRead0(java.base@17.0.8/Native Method)
	at java.net.SocketInputStream.read(java.base@17.0.8/SocketInputStream.java:168)
	at com.acme.payment.gateway.AcquirerClient.capture(AcquirerClient.java:133)
	at com.acme.payment.LedgerService.applyEntry(LedgerService.java:95)
	at com.acme.payment.PaymentFacade.settle(PaymentFacade.java:41)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(java.base@17.0.8/ThreadPoolExecutor.java:1136)
	at java.lang.Thread.run(java.base@17.0.8/Thread.java:833)

   Locked ownable synchronizers:
	- <0x000000061f8a2b40> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)
```

After:

```
"t426f3xd05a4-1" #15 prio=5 os_prio=31 cpu=4211.03ms elapsed=410.55s tid=0x00007fb2a3813200 nid=0x5203 runnable  [0x000000016d0be000]
   java.lang.Thread.State: RUNNABLE
	at java.net.SocketInputStream.socketRead0(java.base@17.0.8/Native Method)
	at java.net.SocketInputStream.read(java.base@17.0.8/SocketInputStream.java:168)
	at pb536bxc27ec.pc2564xde165.pd98ecx128d7.p9c903xbeb39.C8ce34x79651.ma2f96x923d9(C8ce34x79651.java:133)
	at pb536bxc27ec.pc2564xde165.pd98ecx128d7.Cfcbfdx33dfc.m65719x51697(Cfcbfdx33dfc.java:95)
	at pb536bxc27ec.pc2564xde165.pd98ecx128d7.Cd2933x3b08e.m50b42x62d75(Cd2933x3b08e.java:41)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(java.base@17.0.8/ThreadPoolExecutor.java:1136)
	at java.lang.Thread.run(java.base@17.0.8/Thread.java:833)

# [tm-anon: stripped]
```

The diff is the whole design:

- `pgto-worker-1` became `t426f3xd05a4-1`. The **pool prefix** is tokenized, the
  **`-1` suffix is kept** — pool grouping, starvation and thread-leak detection
  all key off that suffix.
- Each package segment gets its own token, so the package tree keeps its shape
  and flame graphs still parse `package.Class.method(`.
- JDK and framework frames, lock addresses (`<0x…>`), thread states, `cpu=`,
  `tid=`, `nid=`, blank lines: untouched.
- `Locked ownable synchronizers` is stripped: the analyzer ignores it and it
  leaks class names for free. Removed lines become `# [tm-anon: stripped]` so
  the blank-line structure that delimits threads is never disturbed.
- The first line of the output is the marker `# tm-anon v1`.

Same vault, same name, same token — forever, and across dumps. That is what
keeps multi-dump comparison and timelines working after masking.

### 3. Verify before uploading

```
$ tm-anon verify payments-prod.txt payments-prod.anon.txt
tm-anon verify
  original: payments-prod.txt
  masked:   payments-prod.anon.txt

Residual identifiers (must be 0): 0
Structural anchors: 3 checked, all intact
Counts (original -> masked):
  threads:     14 -> 14
  frames:      37 -> 37
  blank lines: 24 -> 24
Tokens in masked file: 46
Stripped lines: 10

PASS - no identifier survived and the structure is intact.
```

`verify` is the command to put in front of an upload, and the one to show a
security reviewer. It re-reads the masked file with fresh eyes and reports any
identifier that is neither a token nor on the allowlist. Exit code `4` when it
fails, and the report names the offending line.

### 4. Unmask the analysis output

`unmask` treats its input as opaque text and rewrites every token it finds, so it
works on export JSON, on CSV, and on prose an LLM wrote about your dump.

```
$ tm-anon unmask analysis-export.json -o analysis-export.plain.json
Wrote analysis-export.plain.json
Restored 11 token occurrence(s), 7 distinct.
```

Before — what the analysis service produced:

```json
"threadsAfetadas": ["t426f3xd05a4-1", "t426f3xd05a4-2"],
"frameTopoComum": "pb536bxc27ec.pc2564xde165.pd98ecx128d7.Cfcbfdx33dfc.m65719x51697",
"descricao": "Two threads of the same pool contend on a ReentrantLock held by t426f3xd05a4-1 inside m65719x51697.",
"vein": "The bottleneck is Cfcbfdx33dfc: it serializes every settlement while an outbound socket read blocks in Cd2933x3b08e."
```

After:

```json
"threadsAfetadas": ["pgto-worker-1", "pgto-worker-2"],
"frameTopoComum": "com.acme.payment.LedgerService.applyEntry",
"descricao": "Two threads of the same pool contend on a ReentrantLock held by pgto-worker-1 inside applyEntry.",
"vein": "The bottleneck is LedgerService: it serializes every settlement while an outbound socket read blocks in PaymentFacade."
```

Note the last two lines: tokens come back **inside prose**, not only in
structured fields. That is why the token grammar is a distinctive
`[pCmt]<hex>x<hex>` shape matched on word boundaries.

---

## Command reference

```
tm-anon init   [--vault <path>]
tm-anon mask   <dump> [-o <out>] [--vault <path>] [--strict] [--report <path>] [--dry-run]
tm-anon unmask <file> [-o <out>] [--vault <path>]
tm-anon verify <original> <masked> [--vault <path>]

Exit codes: 0 ok - 1 usage - 2 unsupported input - 3 vault error - 4 verify failed
```

The vault defaults to `./tm-anon-vault.json` in every command.

### `init`

Creates a vault: a fresh 256-bit key from `SecureRandom` plus an empty token
map. Refuses to overwrite an existing vault (exit `3`). Adds the file to
`.gitignore` when it sits inside a git repository.

### `mask`

Reads a HotSpot-family thread dump and writes the masked copy. Without `-o` the
output is `<name>.anon.<ext>`.

| Option | Effect |
|---|---|
| `-o <out>` | output file |
| `--vault <path>` | vault to use (must exist) |
| `--strict` | also tokenize the *recommended* allowlist (52 well-known open-source package prefixes: Jackson, SLF4J, Netty, Hibernate, Hikari, …). The *required* list is never tokenized — doing so would break detection. |
| `--report <path>` | write counters and warnings to a file |
| `--dry-run` | print the summary, write nothing, leave the vault untouched |

```
$ tm-anon mask payments-prod.txt --dry-run
dry-run: no output written, vault not updated.
lines:  78 preserved, 10 tokenized, 22 stripped, 0 redacted
Reminder: upload the masked file under a neutral file name and title -
the original name often carries the very identifiers you just masked.
```

Report file (`--report r.txt`):

```
tm-anon mask report
input: payments-prod.txt
lines total: 110
preserved: 78
tokenized: 10
stripped: 22
redacted: 0
warnings: 0
```

**Fail-closed.** A line no rule recognizes is replaced by
`# [tm-anon: redacted]`, never passed through verbatim. A file that is not a
recognizable HotSpot dump is refused outright:

```
$ tm-anon mask notadump.txt
tm-anon: unrecognized dump format (fail-closed refusal, SPEC exit 2).
Only HotSpot-family thread dumps are supported: jstack, jcmd Thread.print,
jcmd Thread.dump_to_file -format=text, ThreadMXBean/VisualVM.
```

### `unmask`

Restores real names in any text. Without `-o` the result goes to stdout and the
summary to stderr, so `tm-anon unmask export.json > plain.json` does the obvious
thing. Tokens unknown to the vault are left alone and reported — that usually
means the text was masked with a different vault, which is a fact about the
input rather than an error. Idempotent.

### `verify`

Compliance report over the pair (original, masked): residual identifiers,
structural anchors, thread/frame/blank-line counts, token count. When a vault is
present it also cross-checks that the tokens in the masked file belong to that
vault. Exit `0` on PASS, `4` on FAIL.

## Supported dump formats

HotSpot family, which means OpenJDK and everything built on it (Oracle JDK,
Temurin, Corretto, Zulu, Liberica, Zing, GraalVM in JVM mode):

- `jstack` — JDK 8, 11, 17, 21, 25
- `jcmd Thread.print`
- `jcmd Thread.dump_to_file -format=text` (`#N "name" STATE`)
- `ThreadMXBean` / VisualVM (`"name" Id=N STATE on Class@hash`)
- virtual threads: pinned, mounted on a carrier, unmounted
- deadlock blocks, multi-dump files, header-less and reverse-ordered dumps

Not supported yet: **OpenJ9 javacore** and GraalVM native-image dumps. Both are
refused with exit `2` rather than half-masked. See [`corpus/`](corpus/) for the
17 fixtures every release is tested against.

## Why you can trust this

You are being asked to run a tool over your most sensitive debugging artifact.
Reasons to believe it does what it says, ordered by how easily you can check
them yourself:

1. **There is no network code, and a test enforces that.**
   `NoNetworkArchitectureTest` scans the production sources, the compiled
   bytecode constant pools and `pom.xml` for `java.net`, socket channels,
   `javax.net`, `jdk.net` and any HTTP dependency, and fails the build on the
   first hit. Run it yourself:

   ```
   ./mvnw test -Dtest=NoNetworkArchitectureTest
   ```

2. **Zero runtime dependencies.** The only entry in `pom.xml` is JUnit, at test
   scope. There is no transitive supply chain to audit — the shaded jar contains
   this repository's classes and the allowlist JSON, nothing else. Even the JSON
   parser and the argument parser are small in-tree classes.

3. **The allowlist is a readable JSON file, not a hidden heuristic.**
   [`allowlist/allowlist-v1.json`](allowlist/allowlist-v1.json) is exactly what
   stays verbatim, and [`allowlist/SOURCES.md`](allowlist/SOURCES.md) gives the
   `file:line` origin of every required entry. Disagree with an entry and you can
   see it, change it, and rebuild.

4. **The vault never leaves your filesystem**, because nothing in this jar can
   send it anywhere. Reversal requires the vault. Not the code — the vault.

5. **Everything is tested against a corpus of 17 dumps** with golden
   expectations, plus property tests on the token grammar. `./mvnw test` runs
   the lot; CI runs it on Linux and Windows.

The security argument in full, including what a masked dump still reveals, is in
[THREAT_MODEL.md](THREAT_MODEL.md). It is deliberately written as "here is what
this does not protect you from".

## FAQ

**What exactly does the analysis service see?**
Structure and public names. Thread count and states, pool shapes, JDK and
framework frames, lock addresses, JVM version and vendor, whether there is a
deadlock, and opaque tokens where your names used to be. It never sees a name of
yours, and it has no way to recover one, because the vault stays with you.

**Who can reverse it?**
Whoever holds the vault file. That is the whole answer. A token is
`HMAC-SHA256(vault key, value)` truncated to 40 bits, so without the key you
cannot even *test a guess* — which is why this is keyed HMAC and not a plain
hash. `SHA-256("com.acme.OrderService")` would fall to a dictionary attack in
seconds; Java names are extremely guessable.

**What happens if I lose the vault?**
Already-masked dumps become permanently unreadable. Tokens are recomputable from
the key, but the reverse map lives in the vault and nowhere else. Back it up.
Treat it like an SSH private key.

**Can I share the vault with my team?**
Yes, and it is the normal setup: put it in the secret store the team already
uses. Same tokens on every machine, everyone can unmask. Understand the trade —
sharing the vault is sharing the ability to reverse every dump masked with it.

**Will the analysis still be correct?**
Same detections, same health score. That is the design goal, and it is what the
allowlist exists for. Two known deviations, documented rather than hidden:
application frames that today match detection patterns *by accident* (fragments
without a package, like `Consumer.receive`) stop matching, and schedulers with a
custom thread-name prefix fall back to stack-based detection. The honest claim is
"equivalent analysis", not "byte-identical".

**Does the file name leak anything?**
Yes, and `tm-anon` cannot fix that for you, which is why `mask` reminds you every
run. Uploading `payments-prod-tenant-acme.txt` defeats the entire exercise. Use
a neutral file name and title.

**Do I need to trust the ThreadMine service to use this?**
No. `tm-anon` is a standalone MIT-licensed CLI with no network code. It is built
by the people behind ThreadMine, and it works with any thread dump analyzer, or
with none at all.

## Build and test

```bash
./mvnw package                                 # shaded jar in target/
./mvnw test                                    # full suite
./mvnw test -Dtest=NoNetworkArchitectureTest   # the audit test alone
```

CI builds and runs the full suite on Linux and Windows for every push and pull
request. Releases are cut from `v*` tags and ship the jar plus native binaries
for Linux, macOS and Windows, each smoke-tested (mask + verify against a real
fixture) before publication.

## Contributing

Bug reports about dumps `tm-anon` masks badly are the most valuable thing you can
send — but **never attach a real dump**. Reduce it to a synthetic fixture in the
style of [`corpus/fixtures/`](corpus/fixtures/) (fictional `com.acme.*`
namespace) and attach that instead.

## License

[MIT](LICENSE)

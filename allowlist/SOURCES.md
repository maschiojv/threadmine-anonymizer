# SOURCES — why each `required` allowlist entry exists

**Artifact:** [allowlist-v1.json](allowlist-v1.json) · **Version:** 1

The allowlist is the list of names `tm-anon` must **not** mask. Everything on it is public
infrastructure — JDK internals, application servers, drivers, well-known libraries — and every
entry is here for one reason: **the analyzer matches on it**. Masking one of these names would
not protect you from anything (they are nobody's secret) and would silently break a detection,
which is the failure mode that matters: a dump that looks analyzed but quietly lost a finding.

This document is the rationale, entry family by entry family, so you can decide for yourself
whether each one deserves to survive masking. What gets tokenized instead — your packages,
classes, methods and thread names — is defined by the rewriting rules, not by this file.

**Two tiers.** `required` entries are what the analyzer's detectors and parsers match by name;
losing one costs a detection. `recommended` entries are widely used public libraries that are
not matched by name but are not secrets either. They are preserved by default and tokenized
when you pass `--strict`, which is the switch to reach for if your threat model says even your
dependency list is sensitive.

**Matching is longest-prefix** for packages. Where the analyzer matches a narrow prefix
(`org.apache.tomcat.`) and a broad one (`org.apache.`), the broad one is what is recorded: the
allowlist is the union, and the shortest prefix wins.

---

## 1. `required.packagePrefixes` (30 entries)

| Prefix | Why it must survive |
|---|---|
| `java.` `javax.` `jakarta.` `jdk.` `sun.` `com.sun.` | JDK and Java EE/Jakarta frames. They identify blocking I/O, network reads, JDBC calls, queue waits and idle pools — the raw material of nearly every detector. |
| `org.apache.` | Tomcat, Coyote, Catalina, HttpClient, Commons DBCP, Kafka clients, ActiveMQ/Qpid. Drives HTTP pool and consumer detection. |
| `org.eclipse.` | Jetty. Same role as Tomcat above. |
| `org.springframework.` | RestTemplate/WebClient, Kafka and JMS listeners, AMQP, scheduling. |
| `org.quartz.` | Scheduler detection. |
| `org.hibernate.` | ORM frames, used to tell an ORM-driven query from application code. |
| `org.jboss.` `org.wildfly.` `org.xnio.` `io.undertow.` | JBoss/WildFly stack, including its enhanced queue executor and XNIO workers. |
| `io.netty.` | Event loops (epoll/kqueue/NIO), which look busy unless recognized as idle. |
| `io.grpc.` | Kept for a subtle reason worth knowing: gRPC ships a **shaded** copy of Netty, so its idle I/O frames read as `io.grpc.netty.shaded.io.netty.channel.epoll.…`. The analyzer matches these as substrings; masking `io.grpc.` would break the match and an idle I/O worker would start looking busy. |
| `reactor.` | Reactor Netty pools and schedulers. |
| `kotlin.` `scala.` | Runtime frames of JVM languages, not application code. |
| `okhttp3.` `feign.` | HTTP clients — outbound-call detection. |
| `org.postgresql.` `com.mysql.` `oracle.jdbc.` | JDBC drivers — identify a thread parked inside a query. |
| `com.zaxxer.hikari.` `com.mchange.v2.c3p0.` | Connection pools — connection-starvation detection. |
| `com.rabbitmq.` `com.amazonaws.` `software.amazon.awssdk.` | Message consumers (RabbitMQ, SQS) — idle-consumer detection. |

**Frame fragments without a package.** The analyzer also matches a few bare fragments
(`KafkaConsumer.poll`, `Consumer.receive`, `MessageConsumer.receive`, `Channel.basicConsume`,
`ReceiveMessage`). These are not package prefixes and cannot live in this list, but the classes
that actually produce them all sit under prefixes already required above, so the match survives
masking. Residual effect, declared: an application class of your own that happens to be named
`Consumer.receive` stops matching. That removes a false positive rather than creating one.

---

## 2. `required.threadNameExact` (0 entries)

Empty on purpose. No thread name is matched by exact equality — matching is by prefix, suffix or
regex. A full name like `Reference Handler` therefore lives in `threadNamePrefixes`, because that
is how it is actually matched; demoting it to an exact match would change behaviour for names
like `Reference Handler-2`.

---

## 3. `required.threadNamePrefixes` (44 entries)

Semantics: `name.startsWith(entry)` → the **whole** name is preserved.

- **JVM internals:** `Reference Handler`, `Finalizer`, `Signal Dispatcher`, `Attach Listener`,
  `Common-Cleaner`, `Cleaner-`, `Notification Thread`, `Service Thread`,
  `Monitor Deflation Thread`, `DestroyJavaVM`, `Jndi-Dns-`.
- **JIT compiler:** `C1 CompilerThread`, `C2 CompilerThread`.
- **Garbage collectors:** `GC `, `GC Thread`, `G1 `, `ZGC `, `Shenandoah `.
- **VM threads:** `VM Thread`, `VM Periodic Task`, `VM Periodic Task Thread`.
- **Loom runtime:** `VirtualThread-unblocker`, `Read-Poller`, `Write-Poller`.
- **JDK utilities:** `Timer`, `TimerQueue`.
- **Application servers:** `Catalina-utility-`, `parallel-`, `reactor-http-nio-`,
  `reactor-tcp-nio-`, `MSC service thread`, `Reference Reaper`, `ServerService Thread Pool`,
  `Periodic Recovery`, `Transaction Reaper`, `Transaction Expired Entry Monitor`, `IdleRemover`,
  `ConnectionValidator`, `DeploymentScanner-threads`.
- **Framework schedulers (default names only):** `scheduling-`, `TaskScheduler-`,
  `ThreadPoolTaskScheduler-`, `QuartzScheduler_`, `DefaultQuartzScheduler`. Note that these
  prefixes are configurable in your application; a custom one is treated as your name and gets
  tokenized, and scheduler detection then falls back to matching the stack instead.

Some entries are subsumed by shorter ones (`GC Thread` by `GC `, `TimerQueue` by `Timer`). They
are kept anyway: redundancy is harmless in a match set and makes the list verifiable line by line.

---

## 4. `required.threadNameSuffixes` (3 entries)

Semantics: `name.endsWith(entry)` → the whole name is preserved.

`-Acceptor`, `-Poller`, `-ClientPoller` — HTTP connector threads, named by suffix rather than
prefix by Tomcat and friends.

---

## 5. `required.threadNameRegexes` (11 entries)

| Regex | What breaks if it is masked |
|---|---|
| `^http-nio-\d+-exec-\d+$` (Tomcat) | pool exhaustion, stuck request |
| `^qtp\d+-\d+$` (Jetty) | idem |
| `^XNIO-\d+-task-\d+$` (Undertow) | idem |
| `^default-task-\d+$` | idem |
| `^Thread-\d+$` | orphan thread, thread leak |
| `^(default\|XNIO-\d+) (I/O\|Accept)(-\d+)?$` | idle-I/O fallback for threads with no stack |
| `(?i)^(GC \|G1 \|C4 \|ZGC \|Shenandoah \|Concurrent Mark\|ParallelGC)` | thread classified as GC — counters and UI filters |
| `(?i)^(C[12] \|Compiler)` | thread classified as compiler |
| `(?i)^(VM \|Signal \|Finalizer\|Reference Handler\|Attach Listener)` | thread classified as VM |
| `^VirtualThread\[.*` | virtual-thread classification: pinning detection and Loom metrics |
| `^ForkJoinPool-\d+-worker-\d+$` | carrier grouping for virtual threads |

Two notes for anyone applying these regexes directly:

- Case-insensitive patterns carry an inline `(?i)` rather than relying on a flag, because JSON
  cannot express one. Without it, a lowercase `gc thread#1` would be missed.
- `^ForkJoinPool-\d+-worker-\d+$` is the one entry not derived from a name match: it is the JDK's
  default carrier-thread name, it contains nothing of yours, and preserving it is what keeps a
  Loom diagnosis readable.

---

## 6. `required.structuralMarkers` and `structuralMarkerRegexes`

These are not identifiers at all — they are format anchors: `Full thread dump`,
`java.lang.Thread.State:`, thread states, header fields (`daemon`, `prio=`, `cpu=`, `tid=`,
`nid=`), lock lines (`- locked <`, `- waiting on`, `- parking to wait for`, `(a `), deadlock
block markers, the Loom markers (`<pinned: synchronized>`, `<virtual thread is mounted on carrier
thread `, `Carrying virtual thread #`), the `no object reference available` sentinel, the
OpenJ9 javacore tokens (`1TISIGINFO`, `3XMTHREADINFO`, `1XMJAVAVERSION`), and the double quote
that delimits every thread name.

Masking any of them does not hide a secret; it destroys the parse. The regex entries are
**frames**: everything outside the capture group is preserved verbatim, and only what is captured
is subject to the rewriting rules — a lock line keeps its address and gets its class tokenized,
a carrier marker keeps its wording and gets the thread name inside it tokenized.

---

## 7. Known risk of this allowlist

**A broad prefix can preserve one of your names.** `Timer`, `parallel-`, `GC `, `Finalizer` and
friends match by `startsWith`, so an application thread whose name begins with one of them is
written out **verbatim**. A thread you called `TimerBillingTenantAcme` would survive masking.

This is deliberate, and the trade-off is worth stating plainly: the analyzer already treats such
a thread as JVM-internal, so preserving it is what keeps detection identical — but it is a real
leak path. Two mitigations: read the `verify` output, which lists what survived, and use
`--strict` if you would rather over-mask than risk it. If you name pools after tenants,
customers or systems, this is the paragraph to reread before uploading.

**The allowlist tracks one version of the analyzer.** If the analyzer starts matching a pattern
that is not mirrored here, detection degrades quietly rather than loudly. A contract test on the
analyzer side is what keeps the two in step.

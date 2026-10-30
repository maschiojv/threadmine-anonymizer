# SOURCES — why each `required` allowlist entry exists

**Artifact:** [allowlist-v3.json](allowlist-v3.json) · **Version:** 3 · previous: [allowlist-v2.json](allowlist-v2.json), kept as history

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

**What version 3 adds.** ThreadMine tells you what each thread *is* (HTTP worker, Kafka client,
connection-pool housekeeper, scheduler…) from its name, through a role catalog
(`CatalogoPapelThread` in the analyzer, pinned by `CatalogoPapelThreadAllowlistTest`). Version 2
preserved none of about 70 of those names: in a masked dump `HikariPool-1:housekeeper`, `task-3` or
`lettuce-nioEventLoop-4-1` became tokens and the thread lost its role. Version 3 brings every one of
them in, under one rule: **only text a framework or the JDK generates, never a segment that can
carry your data.** A name that is generated in full goes in whole (exact or regex). A name with a part
you choose — a Kafka client id, a pool name, an IP — goes in as a *template* (§6): the generated part
stays, your part is tokenized like any other thread name. §9 lists the decision for each name.

**Matching is longest-prefix** for packages. Where the analyzer matches a narrow prefix
(`org.apache.tomcat.`) and a broad one (`org.apache.`), the broad one is what is recorded: the
allowlist is the union, and the shortest prefix wins.

---

## 1. `required.packagePrefixes` (31 entries)

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
| `com.zaxxer.hikari.` `com.mchange.v2.c3p0.` `com.mchange.v2.resourcepool.` | Connection pools — connection-starvation detection. `com.mchange.v2.resourcepool.` holds `BasicResourcePool.awaitAvailable`, where a c3p0 request waits for a connection. |
| `com.rabbitmq.` `com.amazonaws.` `software.amazon.awssdk.` | Message consumers (RabbitMQ, SQS) — idle-consumer detection. |

**Frame fragments without a package.** The analyzer also matches a few bare fragments
(`KafkaConsumer.poll`, `Consumer.receive`, `MessageConsumer.receive`, `Channel.basicConsume`,
`ReceiveMessage`). These are not package prefixes and cannot live in this list, but the classes
that actually produce them all sit under prefixes already required above, so the match survives
masking. Residual effect, declared: an application class of your own that happens to be named
`Consumer.receive` stops matching. That removes a false positive rather than creating one.

---

## 2. `required.threadNameExact` (31 entries)

Semantics: `name.equals(entry)`. New in version 3, for fixed names of the role catalog that carry no
number and no variable part: `main`, `restartedMain`, `RMI Reaper`, `Sweeper thread`, `process reaper`, `Java2D Disposer`, `Surrogate Locker Thread (Concurrent GC)`, `vitals sampler thread`, `Attach API wait loop`, `file lock watchdog`, `ClassCache Reaper`, `JIT-SamplerThread`, `JIT IProfiler`, `ListenThread.Default`, `Keep-Alive-Timer`, `Keep-Alive-SocketCleaner`, `OkHttp ConnectionPool`, `OkHttp TaskRunner`, `OkHttp Dispatcher`, `Okio Watchdog`, `Connection evictor`, `idle-connection-evictor`, `mysql-cj-abandoned-connection-cleanup`, `Abandoned connection cleanup thread`, `commons-pool-evictor`, `commons-pool-evictor-thread`, `PostgreSQL-JDBC-Cleaner`, `micrometer-kafka-metrics`, `ContainerBackgroundProcessor[StandardEngine[Catalina]]`, `weblogic.time.TimeEventGenerator`, `VDE Transaction Processor Thread`.

Exact is the narrowest tier on purpose: `main` is preserved, `main-billing` is not. The JVM-internal
names that version 2 already matched by prefix (`Reference Handler`, …) stay where they were.

---

## 3. `required.threadNamePrefixes` (47 entries)

Semantics: `name.startsWith(entry)` → the **whole** name is preserved.

- **JVM internals:** `Reference Handler`, `Finalizer`, `Signal Dispatcher`, `Attach Listener`,
  `Common-Cleaner`, `Cleaner-`, `Notification Thread`, `Service Thread`,
  `Monitor Deflation Thread`, `DestroyJavaVM`, `Jndi-Dns-`.
- **JIT compiler:** `C1 CompilerThread`, `C2 CompilerThread`.
- **Garbage collectors:** `GC `, `GC Thread`, `G1 `, `ZGC `, `Shenandoah `.
- **VM threads:** `VM Thread`, `VM Periodic Task`, `VM Periodic Task Thread`.
- **Loom runtime:** `VirtualThread-unblocker` (24+), `VirtualThread-unparker` (21–23), `Read-Poller`,
  `Write-Poller`, `Read-Updater`, `Write-Updater` (21), and the JDK 25 carrier-pool timer
  `ForkJoinPool-N-delayScheduler` (regex below). All appear in the real dumps of `generatedFrom.files`.
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

## 4. `required.threadNameSuffixes` (0 entries in version 3)

Semantics: `name.endsWith(entry)` → the whole name is preserved.

Version 2 listed `-Acceptor`, `-Poller`, `-ClientPoller` here (HTTP connector threads, named by
suffix by Tomcat and friends). A suffix keeps everything in front of it, so a Tomcat connector bound
with `address=` (`http-nio-10.0.0.5-8080-Acceptor`) kept its IP verbatim, and so did any
application thread ending in `-Poller`. Version 3 empties this tier: Tomcat's default names are
regexes (§5), a connector with an address goes through the Tomcat template (§6), and the last
template in §6 keeps only the suffix and masks what comes before it (`acme-Poller` →
`t5d1e7x9a0b3-Poller`). The analyzer's suffix check still sees `-Acceptor` / `-Poller`.

---

## 5. `required.threadNameRegexes` (50 entries)

| Regex | What breaks if it is masked |
|---|---|
| `^http-nio-\d+-exec-\d+$` (Tomcat) | pool exhaustion, stuck request |
| `^qtp\d+-\d+$` (Jetty) | idem |
| `^XNIO-\d+-task-\d+$` (Undertow) | idem |
| `^(default[- ]task\|XNIO-\d+ task)-\d+$` (WildFly, v3) | idem. Version 2 had `^default-task-\d+$`; WildFly 10+ names its workers `default task-N` (with a space) and Undertow 2.x `XNIO-N task-N`, so the analyzer's HTTP-pool detectors now accept all three and the allowlist follows |
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

**Added in version 3** (role catalog, §9): every regex is anchored at both ends and is made of fixed
words, digits and fixed punctuation only, so a name it preserves cannot hold anything you chose.
Families: JMX/RMI (`RMI TCP Accept-N`, `RMI Scheduler(N)`, `JMX … N`), JIT threads outside classic
HotSpot (JVMCI, OpenJ9 `JIT Compilation Thread-N`), Tomcat connectors over HTTPS/AJP/NIO2/APR,
`NioBlockingSelector`, the WebLogic execute queues **of WebLogic itself** (`weblogic.kernel.Default`,
`.System`, `.Non-Blocking`, `weblogic.socket.Muxer`, `weblogic.admin.HTTP|RMI`, `JMS.TimerClientPool`;
a queue you define is tokenized), the JDK HttpClient, Apache HttpClient dispatchers, HikariCP and Druid
helpers with the **default** pool name, Spring Kafka/AMQP/JMS listener containers with the **default**
id, `DefaultMessageListenerContainer-N`, ActiveMQ session tasks, `scheduler-N`, `taskScheduler-N`,
Spring `task-N` and executor defaults, `ForkJoinPool.commonPool-worker-N`, `pool-N-thread-N`,
Log4j/Logback internal threads, Lettuce, Redisson, Reactor Netty (epoll/kqueue/io_uring),
`boundedElastic-N`, Netty event-loop groups, the Micrometer push registries by registry name,
OpenTelemetry and Prometheus exporters, `container-N` and `Catalina-startStop-N`.

---

## 6. `required.threadNameTemplates` (20 entries) — new in version 3

Semantics: the regex must match the **whole** name. Text outside the capture groups is what the
framework generates and stays verbatim; **each capture group is masked like a thread name of its
own** (route marker, numeric suffix, token — SPEC §5.3), so the same pool name gets the same token
everywhere. `verify` accepts a templated name only when every captured part is a token: an unmasked
part is reported as a leak.

    kafka-coordinator-heartbeat-thread | billing-tenant42  ->  kafka-coordinator-heartbeat-thread | t3a9f1x0c2e7
    RMI TCP Connection(3)-10.20.30.40                      ->  RMI TCP Connection(3)-t81b0cx4e2a9
    BillingPool:housekeeper                                ->  t5d1e7x9a0b3:housekeeper

That is what keeps the role (the analyzer matches the generated part) without keeping your text.
The whole-name tiers (§2–§5) are tried first, so a fully generated name such as
`HikariPool-1:housekeeper` stays verbatim and only a custom pool name reaches the template. A
template without a capture group is rejected when the allowlist is loaded: it would keep the whole
name, which is a regex entry and must be argued as one.

| Template |
|---|
| `^RMI TCP Connection\(\d+\)-(.+)$` |
| `^RMI (?:RenewClean\|ConnectionExpiration)-\[(.+)\]$` |
| `^(?:https?\|ajp)-(?:jsse-\|openssl-)?(?:nio2?\|apr\|bio)-(.+)-\d+-(?:exec-\d+\|(?:Acceptor\|ClientPoller\|Poller\|AsyncTimeout)(?:-\d+)?)$` |
| `^qtp\d+-\d+-acceptor-\d+@(.+)$` |
| `^ListenThread\.(.+)$` |
| `^OkHttp (.+)$` |
| `^(.+)[: ](?:housekeeper\|connection adder\|connection closer)$` |
| `^kafka-(?:producer-network-thread\|coordinator-heartbeat-thread\|admin-client-thread) \\| (.+)$` |
| `^(.+)-StreamThread-\d+$` |
| `^(.+)-\d+-C-\d+$` |
| `^AMQP Connection (.+)$` |
| `^ActiveMQ (?:Transport\|Connection Executor): (.+)$` |
| `^(.+)_(?:Worker-\d+\|QuartzSchedulerThread)$` |
| `^AsyncAppender-Worker-(.+)$` |
| `^Log4j2-(.+)$` |
| `^micrometer-(.+)$` |
| `^(.+)-metrics-publisher$` |
| `^ContainerBackgroundProcessor\[StandardEngine\[(.+)\]\]$` |
| `^weblogic\.(.+)$` |
| `^(.+)-(?:Acceptor\|ClientPoller\|Poller)(?:-\d+)?$` — connector suffixes (§4); last, so the Tomcat template wins for a connector name |

## 7. `required.structuralMarkers` and `structuralMarkerRegexes`

These are not identifiers at all — they are format anchors: `Full thread dump`,
`java.lang.Thread.State:`, thread states, header fields (`daemon`, `prio=`, `cpu=`, `tid=`,
`nid=`), lock lines (`- locked <`, `- waiting on`, `- parking to wait for`, `(a `), deadlock
block markers, the Loom markers the JDK really prints (`Carrying virtual thread #` from JDK 21,
`Mounted virtual thread #` from JDK 24, the `virtual` header token and the
`java.lang.VirtualThread.parkOnCarrierThread` pin frame), the `no object reference available` sentinel, the
OpenJ9 javacore tokens (`1TISIGINFO`, `3XMTHREADINFO`, `1XMJAVAVERSION`), and the double quote
that delimits every thread name.

Masking any of them does not hide a secret; it destroys the parse. The regex entries are
**frames**: everything outside the capture group is preserved verbatim, and only what is captured
is subject to the rewriting rules — a lock line keeps its address and gets its class tokenized,
a thread header keeps `#N` and `virtual` and gets the quoted name tokenized.

**Version 2 (this release).** Removed `<pinned: synchronized>` and
`<virtual thread is mounted on carrier thread "...">`: no JDK prints them (they came from synthetic
fixtures; ThreadMine's parser dropped them too). Added what the JDK does print, taken from real
dumps of JDK 21–25 (`generatedFrom.files`): `Carrying virtual thread #N` (21+), `Mounted virtual
thread #N` (24+), `#N "" virtual` headers (21–24) and `#N "" virtual STATE <instant>` (25),
frames with and without `at `, and `parkOnCarrierThread`. The `CarrierThreads` thread group named
in the original brief appears in none of those dumps, so it is not listed.

---

## 8. Known risk of this allowlist

**A broad prefix can preserve one of your names.** `Timer`, `parallel-`, `GC `, `Finalizer` and
friends match by `startsWith`, so an application thread whose name begins with one of them is
written out **verbatim**. A thread you called `TimerBillingTenantAcme` would survive masking.

This is deliberate, and the trade-off is worth stating plainly: the analyzer already treats such
a thread as JVM-internal, so preserving it is what keeps detection identical — but it is a real
leak path. Two mitigations: read the `verify` output, which lists what survived, and use
`--strict` if you would rather over-mask than risk it. If you name pools after tenants,
customers or systems, this is the paragraph to reread before uploading.

**A template keeps the shape of a name.** `t81b0cx4e2a9:housekeeper` tells a reader that a
connection pool exists, not what it is called. That is the trade the role catalog needs, and it is
the same information the stack frames (`com.zaxxer.hikari.`) already give away.

**The allowlist tracks one version of the analyzer.** If the analyzer starts matching a pattern
that is not mirrored here, detection degrades quietly rather than loudly. A contract test on the
analyzer side is what keeps the two in step.

---

## 9. Role catalog names: one decision per name (version 3)

The working list is `NAO_PRESERVADOS_CONHECIDOS` as of the analyzer commit in
`generatedFrom.commit`: the real example names of `CatalogoPapelThread` that version 2 did not
preserve. Each one now has a tier; none was left out. The analyzer's test masks every example the
way `tm-anon` does and checks that it lands in the same role.

| Name (real example) | Tier | Entry |
|---|---|---|
| `RMI TCP Accept-0` | regex | `^RMI TCP Accept-\d+$` |
| `RMI TCP Connection(2)-10.0.0.5` | template | `^RMI TCP Connection\(\d+\)-(.+)$` |
| `RMI Scheduler(0)` | regex | `^RMI Scheduler\(\d+\)$` |
| `RMI Reaper` | exact | `RMI Reaper` |
| `JMX server connection timeout 21` | regex | `^JMX (server connection timeout\|client heartbeat) \d+$` |
| `JVMCI CompilerThread-1` | regex | `^JVMCI(-native)? CompilerThread-?\d+$` |
| `JIT Compilation Thread-000` | regex | `^JIT (Diagnostic )?Compilation Thread-\d+( Suspended)?$` |
| `JIT-SamplerThread` | exact | `JIT-SamplerThread` |
| `Sweeper thread` | exact | `Sweeper thread` |
| `process reaper` | exact | `process reaper` |
| `vitals sampler thread` | exact | `vitals sampler thread` |
| `Attach API wait loop` | exact | `Attach API wait loop` |
| `Surrogate Locker Thread (Concurrent GC)` | exact | `Surrogate Locker Thread (Concurrent GC)` |
| `main` | exact | `main` |
| `restartedMain` | exact | `restartedMain` |
| `http-nio-8080-Acceptor-0` | regex | `^(https?\|ajp)-(jsse-\|openssl-)?(nio2?\|apr\|bio)-\d+-(Acceptor\|ClientPoller\|Poller\|AsyncTimeout)(-\d+)?$` |
| `qtp1338823963-15-acceptor-0@5d2a2f86-ServerConnector@4b1d6571{HTTP/1.1}{0.0.0.0:8080}` | template | `^qtp\d+-\d+-acceptor-\d+@(.+)$` |
| `ListenThread.Default` | exact | `ListenThread.Default` |
| `http-nio-8080-ClientPoller-0` | regex | `^(https?\|ajp)-(jsse-\|openssl-)?(nio2?\|apr\|bio)-\d+-(Acceptor\|ClientPoller\|Poller\|AsyncTimeout)(-\d+)?$` |
| `NioBlockingSelector.BlockPoller-1` | regex | `^NioBlockingSelector\.BlockPoller-\d+$` |
| `ExecuteThread: '0' for queue: 'weblogic.socket.Muxer'` | regex | `^(\[(ACTIVE\|STANDBY\|STUCK)\] )?ExecuteThread: '\d+' for queue: '(weblogic\.(kernel\.Default( \(self-tuning\))?\|kernel\.System\|kernel\.Non-Blocking\|socket\.Muxer\|admin\.(HTTP\|RMI))\|JMS\.TimerClientPool)'$` |
| `https-jsse-nio-8443-exec-1` | regex | `^(https?\|ajp)-(jsse-\|openssl-)?(nio2?\|apr\|bio)-\d+-exec-\d+$` |
| `ajp-nio-8009-exec-2` | regex | `^(https?\|ajp)-(jsse-\|openssl-)?(nio2?\|apr\|bio)-\d+-exec-\d+$` |
| `http-nio-127.0.0.1-8080-exec-1` | template | `^(?:https?\|ajp)-(?:jsse-\|openssl-)?(?:nio2?\|apr\|bio)-(.+)-\d+-(?:exec-\d+\|(?:Acceptor\|ClientPoller\|Poller\|AsyncTimeout)(?:-\d+)?)$` |
| `XNIO-1 task-1` | regex | `^(default[- ]task\|XNIO-\d+ task)-\d+$` |
| `default task-314` | regex | `^(default[- ]task\|XNIO-\d+ task)-\d+$` |
| `ExecuteThread: '3' for queue: 'weblogic.kernel.Default'` | regex | `^(\[(ACTIVE\|STANDBY\|STUCK)\] )?ExecuteThread: '\d+' for queue: '(weblogic\.(kernel\.Default( \(self-tuning\))?\|kernel\.System\|kernel\.Non-Blocking\|socket\.Muxer\|admin\.(HTTP\|RMI))\|JMS\.TimerClientPool)'$` |
| `[ACTIVE] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'` | regex | `^(\[(ACTIVE\|STANDBY\|STUCK)\] )?ExecuteThread: '\d+' for queue: '(weblogic\.(kernel\.Default( \(self-tuning\))?\|kernel\.System\|kernel\.Non-Blocking\|socket\.Muxer\|admin\.(HTTP\|RMI))\|JMS\.TimerClientPool)'$` |
| `HttpClient-1-SelectorManager` | regex | `^HttpClient-\d+-(SelectorManager\|Worker-\d+)$` |
| `Keep-Alive-Timer` | exact | `Keep-Alive-Timer` |
| `OkHttp ConnectionPool` | exact | `OkHttp ConnectionPool` |
| `Okio Watchdog` | exact | `Okio Watchdog` |
| `Connection evictor` | exact | `Connection evictor` |
| `I/O dispatcher 3` | regex | `^I/O dispatcher \d+$` |
| `HikariPool-1:housekeeper` | regex | `^HikariPool-\d+[: ](housekeeper\|connection adder\|connection closer)$` |
| `HikariPool-1 housekeeper` | regex | `^HikariPool-\d+[: ](housekeeper\|connection adder\|connection closer)$` |
| `HikariPool-1 connection adder` | regex | `^HikariPool-\d+[: ](housekeeper\|connection adder\|connection closer)$` |
| `HikariPool-1 connection closer` | regex | `^HikariPool-\d+[: ](housekeeper\|connection adder\|connection closer)$` |
| `mysql-cj-abandoned-connection-cleanup` | exact | `mysql-cj-abandoned-connection-cleanup` |
| `commons-pool-evictor` | exact | `commons-pool-evictor` |
| `PostgreSQL-JDBC-Cleaner` | exact | `PostgreSQL-JDBC-Cleaner` |
| `kafka-producer-network-thread \| producer-1` | template | `^kafka-(?:producer-network-thread\|coordinator-heartbeat-thread\|admin-client-thread) \\| (.+)$` |
| `kafka-coordinator-heartbeat-thread \| grupo` | template | `^kafka-(?:producer-network-thread\|coordinator-heartbeat-thread\|admin-client-thread) \\| (.+)$` |
| `org.springframework.kafka.KafkaListenerEndpointContainer#0-0-C-1` | regex | `^org\.springframework\.kafka\.KafkaListenerEndpointContainer#\d+-\d+-C-\d+$` |
| `AMQP Connection 10.0.0.7:5672` | template | `^AMQP Connection (.+)$` |
| `org.springframework.amqp.rabbit.RabbitListenerEndpointContainer#0-1` | regex | `^org\.springframework\.amqp\.rabbit\.RabbitListenerEndpointContainer#\d+-\d+$` |
| `DefaultMessageListenerContainer-1` | regex | `^DefaultMessageListenerContainer-\d+$` |
| `ActiveMQ Session Task-1` | regex | `^ActiveMQ Session Task-\d+$` |
| `scheduler-1` | regex | `^(scheduler\|taskScheduler)-\d+$` |
| `taskScheduler-2` | regex | `^(scheduler\|taskScheduler)-\d+$` |
| `MeuScheduler_Worker-1` | template | `^(.+)_(?:Worker-\d+\|QuartzSchedulerThread)$` |
| `task-1` | regex | `^(task\|SimpleAsyncTaskExecutor\|ThreadPoolTaskExecutor\|applicationTaskExecutor)-\d+$` |
| `ForkJoinPool.commonPool-worker-1` | regex | `^ForkJoinPool\.commonPool-worker-\d+$` |
| `pool-3-thread-7` | regex | `^pool-\d+-thread-\d+$` |
| `SimpleAsyncTaskExecutor-1` | regex | `^(task\|SimpleAsyncTaskExecutor\|ThreadPoolTaskExecutor\|applicationTaskExecutor)-\d+$` |
| `AsyncAppender-Worker-ASYNC` | template | `^AsyncAppender-Worker-(.+)$` |
| `Log4j2-TF-1-AsyncLogger[AsyncContext@18b4aac2]-1` | regex | `^Log4j2-TF-\d+-(AsyncLogger(Config)?\[AsyncContext@[0-9a-f]+\]\|Scheduled\|ConfigurationFileWatcher)-\d+$` |
| `logback-1` | regex | `^logback-\d+$` |
| `lettuce-nioEventLoop-4-1` | regex | `^lettuce-(nioEventLoop\|epollEventLoop\|kqueueEventLoop\|ioUringEventLoop\|eventExecutorLoop\|timer)-\d+-\d+$` |
| `lettuce-timer-3-1` | regex | `^lettuce-(nioEventLoop\|epollEventLoop\|kqueueEventLoop\|ioUringEventLoop\|eventExecutorLoop\|timer)-\d+-\d+$` |
| `redisson-netty-2-4` | regex | `^redisson-(netty\|timer)-\d+-\d+$` |
| `reactor-http-epoll-1` | regex | `^reactor-(http\|tcp)-(nio\|epoll\|kqueue\|io_uring)-\d+$` |
| `boundedElastic-1` | regex | `^boundedElastic-(evictor-)?\d+$` |
| `nioEventLoopGroup-2-1` | regex | `^(nio\|epoll\|kqueue)EventLoopGroup-\d+-\d+$` |
| `micrometer-kafka-metrics` | exact | `micrometer-kafka-metrics` |
| `datadog-metrics-publisher` | regex | `^(appoptics\|cloudwatch\|datadog\|dynatrace\|elastic\|humio\|influx\|kairos\|logging\|newrelic\|otlp\|signalfx\|stackdriver\|statsd\|wavefront)-metrics-publisher$` |
| `PeriodicMetricReader-1` | regex | `^PeriodicMetricReader-\d+$` |
| `BatchSpanProcessor_WorkerThread-1` | regex | `^BatchSpanProcessor_WorkerThread-\d+$` |
| `prometheus-http-1-1` | regex | `^prometheus-http-\d+-\d+$` |
| `container-0` | regex | `^container-\d+$` |
| `ContainerBackgroundProcessor[StandardEngine[Catalina]]` | exact | `ContainerBackgroundProcessor[StandardEngine[Catalina]]` |
| `weblogic.time.TimeEventGenerator` | exact | `weblogic.time.TimeEventGenerator` |
| `ExecuteThread: '0' for queue: 'weblogic.kernel.System'` | regex | `^(\[(ACTIVE\|STANDBY\|STUCK)\] )?ExecuteThread: '\d+' for queue: '(weblogic\.(kernel\.Default( \(self-tuning\))?\|kernel\.System\|kernel\.Non-Blocking\|socket\.Muxer\|admin\.(HTTP\|RMI))\|JMS\.TimerClientPool)'$` |
| `ExecuteThread: '1' for queue: 'JMS.TimerClientPool'` | regex | `^(\[(ACTIVE\|STANDBY\|STUCK)\] )?ExecuteThread: '\d+' for queue: '(weblogic\.(kernel\.Default( \(self-tuning\))?\|kernel\.System\|kernel\.Non-Blocking\|socket\.Muxer\|admin\.(HTTP\|RMI))\|JMS\.TimerClientPool)'$` |

Left out on purpose (not in the catalog's examples, listed so nobody adds them by accident): a
WebLogic execute queue **you** define (`ExecuteThread: '0' for queue: 'billing.Queue'`) — the queue
name is yours, so the whole name is tokenized, as in version 2; and the OpenJ9 `IProfiler` thread,
which the role catalog does not classify by name.

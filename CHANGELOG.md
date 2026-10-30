# Changelog

## Unreleased

### Added
- `com.mchange.v2.resourcepool.` in `required.packagePrefixes`: a c3p0 request waiting for a connection
  parks in `BasicResourcePool.awaitAvailable`, outside `com.mchange.v2.c3p0.`. ThreadMine reads that frame
  to report an exhausted connection pool, so a masked dump keeps it.

## 0.5.0 (2026-10-26)

### Added
- **Allowlist v3** (`allowlist/allowlist-v3.json`, replaces `allowlist-v2.json` in the jar; v2 stays in
  the repository as history). It adds the thread names of ThreadMine's role catalog, so a masked dump
  keeps what each thread is: JMX/RMI, JIT threads outside classic HotSpot, Tomcat HTTPS/AJP/NIO2
  connectors, WebLogic's own execute queues, JDK/Apache/OkHttp HTTP clients, HikariCP/MySQL/pgjdbc/
  commons-pool helpers, Kafka/RabbitMQ/JMS/ActiveMQ clients, Spring executors and schedulers,
  Log4j2/Logback, Lettuce/Redisson, Reactor/Netty, Micrometer/OpenTelemetry/Prometheus exporters,
  `main`, `container-N`. One rule: only text a framework or the JDK generates. `SOURCES.md` §9 records
  the decision for each name.
- **`threadNameTemplates`** allowlist tier. A template matches the whole thread name; the text outside
  its capture groups stays verbatim, each captured part is masked like a thread name of its own. It is
  how a name with a part you choose keeps its role without keeping your text:
  `kafka-coordinator-heartbeat-thread | <group>`, `RMI TCP Connection(N)-<ip>`, `<pool>:housekeeper`,
  `<listener>-0-C-1`, `OkHttp <url>`. `verify` accepts a templated name only when every captured part
  is a token. A template with no capture group is rejected at load time.
- `threadNameExact` is used for the first time (31 fixed names such as `main`, `RMI Reaper`,
  `Keep-Alive-Timer`).

### Changed
- WildFly worker names: the `default-task-N` regex becomes `^(default[- ]task|XNIO-\d+ task)-\d+$`,
  covering `default task-N` (WildFly 10+) and `XNIO-N task-N` (Undertow 2.x), which the analyzer's
  HTTP-pool detectors now recognize too.
- Corpus expectations: `main`, `ListenThread.Default` and the OpenJ9 `JIT Compilation Thread-N`
  threads move from tokenized to verbatim. The synthetic OpenJ9 classic fixture's application class
  `com.acme.server.ListenThread` is renamed `SocketListener`, so it no longer shares a name with
  WebLogic's real `ListenThread.Default` thread.
- The `threadNameSuffixes` tier is empty. `-Acceptor`, `-Poller` and `-ClientPoller` kept the whole
  name, so a Tomcat connector bound to an address (`http-nio-10.0.0.5-8080-Acceptor`) kept the IP.
  Tomcat's default connector names are regexes now, and a template keeps only the suffix and masks
  the rest (`acme-Poller` becomes `<token>-Poller`).
- `pom.xml` version is `0.5.0`, without `-SNAPSHOT` (the 0.4.1 tag was cut from a `-SNAPSHOT` pom).

### Upgrading
- Dumps masked with 0.4.1 or earlier keep those thread names as tokens and lose their roles in the
  analysis. Re-mask the original dump with 0.5.0 and the same vault.

## 0.4.1 (2026-10-20)

### Changed
- **Allowlist v2** (`allowlist/allowlist-v2.json`, replaces `allowlist-v1.json`). Virtual-thread
  markers now come from real JDK 21-25 dumps (`generatedFrom.files`), not synthetic fixtures.
  - Removed `<pinned: synchronized>` and `<virtual thread is mounted on carrier thread "...">`:
    no JDK prints them. A line like that is now treated as unknown and redacted (fail-closed).
  - Added `Mounted virtual thread #N` (JDK 24+ jstack; before, `mask` redacted every such line),
    the `java.lang.VirtualThread.parkOnCarrierThread` pin frame, and the `#N "" virtual [STATE]`
    and carrier-header patterns to the structural markers.
  - Added JDK-internal thread names that were being tokenized: `VirtualThread-unparker` (21-23),
    `Read-Updater` / `Write-Updater` (21) and `ForkJoinPool-N-delayScheduler` (25).
- `verify` anchors: `Mounted virtual thread #` added, the two false markers dropped.

### Added
- Corpus: 11 real JDK 21-25 dumps (`dump_to_file` text for 21-25, jstack for 21-25, one
  `Thread.print`) with expectations. They mask with 0 redacted lines and pass `verify`.

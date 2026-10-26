package dev.threadmine.anon.allowlist;

import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.verify.AllowlistLookup;
import dev.threadmine.anon.verify.ComplianceVerifier;
import dev.threadmine.anon.verify.VerifyReport;
import dev.threadmine.anon.core.Vault;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Allowlist v3: the thread names of ThreadMine's role catalog survive {@code mask}, and nothing
 * an application can put in a thread name rides along with them.
 *
 * <p>The names below are the real examples the analyzer's catalog test pins
 * ({@code CatalogoPapelThreadAllowlistTest} in thread-forge). Names a framework generates in full
 * stay verbatim; names with a part the application chooses (a Kafka client id, a pool name, an
 * IP) keep only the generated part and get the rest tokenized.</p>
 */
class AllowlistV3ThreadNamesTest {

    /** A thread token as {@code mask} writes it: optional route marker and {@code [-#]N} suffix. */
    private static final Pattern TOKEN =
            Pattern.compile("t(?:[0-9a-f]{5}x[0-9a-f]{5}|[0-9a-f]{7}x[0-9a-f]{7})(?:/q)?(?:[-#]\\d+)?");

    /** Generated in full by the JDK or a framework: must come out of {@code mask} unchanged. */
    static final List<String> VERBATIM = List.of(
            // JMX / RMI
            "RMI TCP Accept-0", "RMI TCP Accept-19999", "RMI Scheduler(0)", "RMI Reaper",
            "JMX server connection timeout 21",
            // JVM services and compilers outside classic HotSpot
            "JVMCI CompilerThread-1", "JIT Compilation Thread-000", "JIT-SamplerThread", "Sweeper thread",
            "process reaper", "vitals sampler thread", "Attach API wait loop",
            "Surrogate Locker Thread (Concurrent GC)",
            "main", "restartedMain",
            // HTTP servers
            "http-nio-8080-Acceptor-0", "ListenThread.Default", "http-nio-8080-ClientPoller-0",
            "NioBlockingSelector.BlockPoller-1", "ExecuteThread: '0' for queue: 'weblogic.socket.Muxer'",
            "https-jsse-nio-8443-exec-1", "ajp-nio-8009-exec-2", "XNIO-1 task-1", "default task-314",
            "ExecuteThread: '3' for queue: 'weblogic.kernel.Default'",
            "[ACTIVE] ExecuteThread: '0' for queue: 'weblogic.kernel.Default (self-tuning)'",
            // HTTP clients
            "HttpClient-1-SelectorManager", "HttpClient-1-Worker-0", "Keep-Alive-Timer",
            "OkHttp ConnectionPool", "Okio Watchdog", "Connection evictor", "I/O dispatcher 3",
            // Connection pools
            "HikariPool-1:housekeeper", "HikariPool-1 housekeeper", "HikariPool-1 connection adder",
            "HikariPool-1 connection closer", "mysql-cj-abandoned-connection-cleanup", "commons-pool-evictor",
            "PostgreSQL-JDBC-Cleaner",
            // Messaging
            "org.springframework.kafka.KafkaListenerEndpointContainer#0-0-C-1",
            "org.springframework.amqp.rabbit.RabbitListenerEndpointContainer#0-1",
            "DefaultMessageListenerContainer-1", "ActiveMQ Session Task-1",
            // Schedulers and executors
            "scheduler-1", "taskScheduler-2", "task-1", "ForkJoinPool.commonPool-worker-1", "pool-3-thread-7",
            "SimpleAsyncTaskExecutor-1",
            // Logging, Redis, Reactor, metrics
            "Log4j2-TF-1-AsyncLogger[AsyncContext@18b4aac2]-1", "logback-1",
            "lettuce-nioEventLoop-4-1", "lettuce-timer-3-1", "lettuce-eventExecutorLoop-1-1", "redisson-netty-2-4",
            "reactor-http-epoll-1", "boundedElastic-1", "nioEventLoopGroup-2-1",
            "micrometer-kafka-metrics", "datadog-metrics-publisher", "PeriodicMetricReader-1",
            "BatchSpanProcessor_WorkerThread-1", "prometheus-http-1-1",
            // Containers
            "container-0", "ContainerBackgroundProcessor[StandardEngine[Catalina]]",
            "weblogic.time.TimeEventGenerator", "ExecuteThread: '0' for queue: 'weblogic.kernel.System'",
            "ExecuteThread: '1' for queue: 'JMS.TimerClientPool'");

    /**
     * Catalog names with a part the application (or the network) chooses, mapped to the generated
     * part that must survive. The rest of the name must be gone.
     */
    static final Map<String, String> TEMPLATED = Map.ofEntries(
            Map.entry("RMI TCP Connection(2)-10.0.0.5", "RMI TCP Connection(2)-"),
            Map.entry("qtp1338823963-15-acceptor-0@5d2a2f86-ServerConnector@4b1d6571{HTTP/1.1}{0.0.0.0:8080}",
                    "qtp1338823963-15-acceptor-0@"),
            Map.entry("http-nio-127.0.0.1-8080-exec-1", "http-nio-"),
            Map.entry("kafka-producer-network-thread | producer-1", "kafka-producer-network-thread | "),
            Map.entry("kafka-coordinator-heartbeat-thread | grupo", "kafka-coordinator-heartbeat-thread | "),
            Map.entry("AMQP Connection 10.0.0.7:5672", "AMQP Connection "),
            Map.entry("MeuScheduler_Worker-1", "_Worker-1"),
            Map.entry("AsyncAppender-Worker-ASYNC", "AsyncAppender-Worker-"),
            Map.entry("http-nio-10.0.0.5-8080-Acceptor", "http-nio-"),
            Map.entry("AcmeGateway-Poller", "-Poller"));

    /**
     * Planted application data next to generated text. Every value on the right is something
     * the application chose (tenant, group, queue, host, IP, route) and must not survive.
     */
    static final Map<String, List<String>> PLANTED = Map.ofEntries(
            Map.entry("kafka-coordinator-heartbeat-thread | acme-billing-tenant42", List.of("acme", "tenant42")),
            Map.entry("kafka-producer-network-thread | acme-payments", List.of("acme", "payments")),
            Map.entry("RMI TCP Connection(3)-10.20.30.40", List.of("10.20.30.40")),
            Map.entry("RMI RenewClean-[10.20.30.40:1099]", List.of("10.20.30.40")),
            Map.entry("AMQP Connection 192.168.1.15:5672", List.of("192.168.1.15")),
            Map.entry("ActiveMQ Transport: tcp://broker.acme.internal:61616", List.of("acme", "broker")),
            Map.entry("http-nio-10.0.0.5-8080-exec-1", List.of("10.0.0.5")),
            Map.entry("AcmeTenantPool:housekeeper", List.of("Acme", "Tenant")),
            Map.entry("OkHttp https://api.acme.com/v1/orders/123", List.of("acme", "orders")),
            Map.entry("ListenThread.acme-admin-channel", List.of("acme")),
            Map.entry("ExecuteThread: '0' for queue: 'acme.billing.Queue'", List.of("acme", "billing")),
            Map.entry("AsyncAppender-Worker-ACME_AUDIT", List.of("ACME", "AUDIT")),
            Map.entry("Log4j2-TF-1-AsyncLogger[acmeCtx]-1", List.of("acme")),
            Map.entry("AcmeQuartz_Worker-1", List.of("Acme")),
            Map.entry("acme-orders-0-C-1", List.of("acme", "orders")),
            Map.entry("acme-orders-3f2a9c1e-77b4-4c39-9c8e-2a1b3c4d5e6f-StreamThread-1", List.of("acme", "3f2a9c1e")),
            Map.entry("acme-metrics-publisher", List.of("acme")),
            Map.entry("micrometer-acme-tenant", List.of("acme")),
            Map.entry("ContainerBackgroundProcessor[StandardEngine[AcmeEngine]]", List.of("Acme")),
            Map.entry("weblogic.acme.TenantSync", List.of("acme", "Tenant")),
            Map.entry("scheduler-acme", List.of("acme")),
            Map.entry("task-acme-1", List.of("acme")),
            Map.entry("lettuce-acme-1-1", List.of("acme")),
            Map.entry("RMI TCP Accept-acme", List.of("acme")),
            // Tomcat connector bound with address=: the v2 suffix tier kept the whole name, IP included
            Map.entry("http-nio-10.0.0.5-8080-Acceptor", List.of("10.0.0.5")),
            Map.entry("https-jsse-nio-192.168.1.15-8443-ClientPoller-0", List.of("192.168.1.15")),
            Map.entry("acme-billing-Poller", List.of("acme", "billing")),
            Map.entry("AcmeGateway-Acceptor-2", List.of("Acme")));

    @TempDir
    Path tempDir;

    private HotspotRewriter rewriter;
    private AllowlistMatcher shipped;

    @BeforeEach
    void setUp() {
        shipped = AllowlistMatcher.fromClasspath();
        rewriter = new HotspotRewriter(new HmacTokenEngine(Vault.create(tempDir.resolve("vault.json"))), shipped);
    }

    @Test
    void theJarShipsTheV3ArtifactByteForByte() throws IOException {
        String artifact = Files.readString(Path.of("allowlist", "allowlist-v3.json"), StandardCharsets.UTF_8);
        try (var in = AllowlistMatcher.class.getResourceAsStream("/allowlist-v3.json")) {
            assertNotNull(in, "allowlist-v3.json missing from the jar");
            String bundled = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            assertEquals(artifact.replace("\r\n", "\n"), bundled.replace("\r\n", "\n"));
        }
        assertTrue(artifact.contains("\"version\": 3"));
        assertTrue(artifact.contains("\"threadNameTemplates\""));
    }

    @Test
    void everyFullyGeneratedCatalogNameSurvivesMask() {
        for (String name : VERBATIM) {
            assertTrue(shipped.allowsThreadName(name), "not allowlisted: " + name);
            assertEquals(name, rewriter.rewriteThreadName(name), "mask changed " + name);
        }
    }

    @Test
    void templatedCatalogNamesKeepOnlyTheGeneratedPart() {
        TEMPLATED.forEach((name, generated) -> {
            assertFalse(shipped.allowsThreadName(name), "would be kept whole: " + name);
            String masked = rewriter.rewriteThreadName(name);
            assertTrue(masked.contains(generated), name + " lost its generated part: " + masked);
            assertTrue(TOKEN.matcher(masked).find(), name + " has no token: " + masked);
            String variable = name.replace(generated, "");
            assertFalse(masked.contains(variable), name + " kept " + variable + ": " + masked);
        });
    }

    @Test
    void plantedApplicationDataNeverSurvives() {
        PLANTED.forEach((name, secrets) -> {
            String masked = rewriter.rewriteThreadName(name);
            for (String secret : secrets) {
                assertFalse(masked.contains(secret), name + " -> " + masked + " still carries " + secret);
            }
        });
    }

    @Test
    void verifyAcceptsTemplatedNamesOnlyOnceMasked() {
        ComplianceVerifier verifier = new ComplianceVerifier(lookup(shipped));
        for (String name : TEMPLATED.keySet()) {
            String original = header(name);
            String masked = header(rewriter.rewriteThreadName(name));

            VerifyReport raw = verifier.verify(original, original);
            assertTrue(raw.residualIdentifiers().stream().anyMatch(f -> f.value().equals(name)),
                    "unmasked " + name + " must be a finding");

            VerifyReport report = verifier.verify(original, masked);
            assertTrue(report.residualIdentifiers().isEmpty(),
                    "masked " + name + " flagged: " + report.residualIdentifiers());
        }
    }

    @Test
    void maskAndVerifyAgreeOnEveryPlantedName() {
        // mask and verify parse the same allowlist twice (lesson of 0.3.1): for every template, the
        // masked name must pass verify and the raw one must be reported.
        ComplianceVerifier verifier = new ComplianceVerifier(lookup(shipped));
        for (String name : PLANTED.keySet()) {
            String original = header(name);
            String masked = header(rewriter.rewriteThreadName(name));

            assertFalse(verifier.verify(original, original).residualIdentifiers().isEmpty(),
                    "unmasked " + name + " must be a finding");
            assertTrue(verifier.verify(original, masked).residualIdentifiers().isEmpty(),
                    "masked " + name + " flagged: " + verifier.verify(original, masked).residualIdentifiers());
        }
    }

    @Test
    void verifyFlagsATemplatedNameWhoseCapturedPartIsNotAToken() {
        ComplianceVerifier verifier = new ComplianceVerifier(lookup(shipped));
        String original = header("kafka-producer-network-thread | acme-payments");
        for (String leaked : List.of(
                "kafka-producer-network-thread | acme-payments",
                "kafka-producer-network-thread | t81b0cx4e2a9-acme",
                "RMI TCP Connection(2)-10.0.0.5",
                "http-nio-10.0.0.5-8080-Acceptor",
                "acme-billing-Poller")) {
            assertTrue(verifier.verify(original, header(leaked)).residualIdentifiers().stream()
                            .anyMatch(f -> f.value().equals(leaked)),
                    "verify accepted " + leaked);
        }
    }

    @Test
    void noWholeNameSuffixTierLeftInV3() {
        // A suffix keeps the whole name: "http-nio-10.0.0.5-8080-Acceptor" kept the bind IP. v3 keeps
        // the connector suffixes through a template instead, so the part before them is masked.
        assertEquals("tX-Acceptor", shipped.applyThreadNameTemplate("acme-Acceptor", part -> "tX"));
        assertFalse(shipped.allowsThreadName("acme-Poller"));
        assertTrue(shipped.allowsThreadName("http-nio-8080-Poller"), "Tomcat default name stays verbatim");
    }

    @Test
    void templateWithoutCaptureGroupIsRejected() {
        assertThrows(AllowlistJson.ParseException.class, () -> AllowlistMatcher.fromJson("""
                {"required": {"threadNameTemplates": ["^kafka-producer-network-thread .*$"]}}
                """));
    }

    @Test
    void templateMasksEveryGroupAndKeepsTheRest() {
        AllowlistMatcher m = AllowlistMatcher.fromJson("""
                {"required": {"threadNameTemplates": ["^pool \\\\[(.+)\\\\] of (.+)$"]}}
                """);
        assertEquals("pool [X] of X", m.applyThreadNameTemplate("pool [a] of b", part -> "X"));
        assertEquals(List.of("a", "b"), m.threadNameTemplateParts("pool [a] of b"));
        assertNull(m.applyThreadNameTemplate("other", part -> "X"));
        assertNull(m.threadNameTemplateParts("my pool [a] of b"),
                "a template matches the whole name, never a slice of it");
    }

    private static String header(String name) {
        return "\"" + name + "\" #1 prio=5 os_prio=0 tid=0x1 nid=0x1 waiting on condition\n"
                + "   java.lang.Thread.State: WAITING (parking)\n"
                + "\tat java.lang.Thread.sleep(Thread.java:1)\n";
    }

    private static AllowlistLookup lookup(AllowlistMatcher matcher) {
        return new AllowlistLookup() {
            @Override
            public boolean allowsFqcn(String fqcnOrPackage) {
                return matcher.allowsFqcn(fqcnOrPackage);
            }

            @Override
            public boolean allowsThreadName(String name) {
                return matcher.allowsThreadName(name);
            }

            @Override
            public List<String> threadNameTemplateParts(String name) {
                return matcher.threadNameTemplateParts(name);
            }
        };
    }
}

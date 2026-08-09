package dev.threadmine.anon.format.json;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.hotspot.FormatDetector;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.format.hotspot.MaskResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code -format=json} dialect (SPEC §6 gap closed in wave 5). The fixture
 * is a real JDK 25 {@code Thread.dump_to_file -format=json} capture with the
 * identifiers swapped for the fictional namespace, so the schema exercised here
 * is the JDK's own, not one invented from documentation.
 */
class JsonThreadDumpRewriterTest {

    private static final Path FIXTURE =
            Path.of("corpus", "fixtures", "jcmd-dump-json-jdk25.txt");

    @TempDir
    Path tempDir;

    private TokenEngine engine;
    private JsonThreadDumpRewriter rewriter;

    @BeforeEach
    void setUp() {
        engine = new HmacTokenEngine(Vault.create(tempDir.resolve("vault.json")));
        rewriter = new JsonThreadDumpRewriter(engine, AllowlistMatcher.fromClasspath());
    }

    private String fixture() throws IOException {
        return Files.readString(FIXTURE, StandardCharsets.UTF_8);
    }

    private Map<?, ?> maskedTree() throws IOException {
        return (Map<?, ?>) Json.parse(rewriter.mask(fixture()).output());
    }

    @Test
    void theDialectIsDetectedAndNotConfusedWithTheTextOne() throws IOException {
        String text = fixture();
        assertTrue(FormatDetector.isJsonThreadDump(text));
        assertFalse(FormatDetector.isHotspot(text),
                "the text detector must not claim a JSON dump - it would be rewritten line by line");
        assertFalse(FormatDetector.isJavacore(text));
    }

    @Test
    void outputIsStillValidJsonAndCarriesTheMarker() throws IOException {
        String masked = rewriter.mask(fixture()).output();
        Map<?, ?> root = (Map<?, ?>) Json.parse(masked);

        assertEquals(JsonThreadDumpRewriter.MARKER_VALUE, root.get(JsonThreadDumpRewriter.MARKER_KEY));
        assertEquals(JsonThreadDumpRewriter.MARKER_KEY, root.keySet().iterator().next(),
                "the marker is the first key so it is as visible as the first line of a text dump");
        assertNotNull(root.get("threadDump"));
        assertTrue(masked.contains("# tm-anon v1"),
                "the literal marker string must survive a substring search");
    }

    @Test
    void nothingFromTheApplicationNamespaceSurvives() throws IOException {
        MaskResult result = rewriter.mask(fixture());
        assertFalse(result.output().contains("acme"),
                "the fictional namespace must never survive masking");
        assertFalse(result.output().contains("LedgerLock"));
        assertFalse(result.output().contains("PaymentWorker"));
        assertFalse(result.output().contains("Bootstrap"));
    }

    @Test
    void theContainerToStringIsTokenizedKeepingItsIdentityHash() throws IOException {
        // The whole reason this dialect needed work: a StructuredTaskScope or
        // custom executor names an application class outside any stack frame.
        String masked = rewriter.mask(fixture()).output();
        assertTrue(fixture().contains("\"container\": \"com.acme.batch.LedgerScope@7a69b07\""),
                "fixture must still plant the leaking container");
        assertFalse(masked.contains("LedgerScope"));
        assertTrue(masked.contains("@7a69b07"), "the identity hash is an address and stays verbatim");
    }

    @Test
    void rootContainerStaysVerbatimAndParentLinksStillResolve() throws IOException {
        Map<?, ?> dump = (Map<?, ?>) maskedTree().get("threadDump");
        List<?> containers = (List<?>) dump.get("threadContainers");

        java.util.Set<Object> names = new java.util.LinkedHashSet<>();
        for (Object container : containers) {
            names.add(((Map<?, ?>) container).get("container"));
        }
        assertTrue(names.contains("<root>"), "the root container is structure, not a name");

        for (Object container : containers) {
            Object parent = ((Map<?, ?>) container).get("parent");
            if (parent != null) {
                // A dangling parent would break the container tree for any
                // consumer; tokens are deterministic, so the link must survive.
                assertTrue(names.contains(parent), "parent link dangles after masking: " + parent);
            }
        }
    }

    @Test
    void lockFieldsAreTokenizedAcrossEveryShapeTheDumperUses() throws IOException {
        String masked = rewriter.mask(fixture()).output();
        // blockedOn / monitorsOwned[].locks[] both carry com.acme.payment.LedgerLock
        assertTrue(fixture().contains("\"blockedOn\""), "fixture must exercise blockedOn");
        assertTrue(fixture().contains("\"monitorsOwned\""), "fixture must exercise monitorsOwned");
        assertTrue(fixture().contains("\"parkBlocker\""), "fixture must exercise parkBlocker");
        assertFalse(masked.contains("com.acme"), "no lock field may keep an application class");
        assertTrue(masked.contains("\"blockedOn\""), "the field itself must survive");
        assertTrue(masked.contains("\"parkBlocker\""));
    }

    @Test
    void routeNamedThreadGetsTheRouteMarker() throws IOException {
        String masked = rewriter.mask(fixture()).output();
        assertTrue(fixture().contains("sync-\\/api\\/orders?id=99887766"),
                "fixture must keep the route-shaped thread name");
        assertFalse(masked.contains("api/orders"));
        assertFalse(masked.contains("99887766"));
        assertTrue(masked.contains("/q"), "a route-shaped name keeps its /q marker (SPEC 5.3b)");
    }

    @Test
    void allowlistThreadsAndFramesStayVerbatim() throws IOException {
        String masked = rewriter.mask(fixture()).output();
        assertTrue(masked.contains("\"Reference Handler\""));
        assertTrue(masked.contains("\"VirtualThread-unblocker\""));
        assertTrue(masked.contains("java.base/java.lang.Thread.sleep"),
                "a JDK frame is public infrastructure and must survive: " + masked.substring(0, 400));
    }

    @Test
    void structuralFieldsSurviveUntouched() throws IOException {
        Map<?, ?> dump = (Map<?, ?>) maskedTree().get("threadDump");
        assertEquals("25.0.2+10-LTS-69", dump.get("runtimeVersion"));
        assertNotNull(dump.get("processId"));
        assertNotNull(dump.get("time"));

        List<?> containers = (List<?>) dump.get("threadContainers");
        Map<?, ?> root = (Map<?, ?>) containers.get(0);
        assertNotNull(root.get("threadCount"));
        for (Object thread : (List<?>) root.get("threads")) {
            Map<?, ?> t = (Map<?, ?>) thread;
            assertNotNull(t.get("tid"), "tid identifies a thread without naming it");
            assertNotNull(t.get("state"));
        }
    }

    @Test
    void anUnknownKeyIsRedactedRatherThanPassedThrough() {
        // A future JDK field must not ride through a rewriter that never heard
        // of it - the structural form of SPEC 5.8.
        MaskResult result = rewriter.mask("""
                {
                  "threadDump": {
                    "processId": "1",
                    "secretFutureField": "com.acme.Leaky@1234",
                    "threadContainers": []
                  }
                }
                """);
        assertFalse(result.output().contains("acme"));
        assertTrue(result.output().contains("# [tm-anon: redacted]"));
        assertEquals(1, result.redactedLines());
        assertFalse(result.warnings().isEmpty());
    }

    @Test
    void unknownThreadLevelKeyIsRedactedToo() {
        MaskResult result = rewriter.mask("""
                {
                  "threadDump": {
                    "threadContainers": [
                      {
                        "container": "<root>",
                        "threads": [
                          {"tid": "1", "name": "main", "state": "RUNNABLE",
                           "stack": [], "newInJdk99": "com.acme.Secret@ff"}
                        ],
                        "threadCount": "1"
                      }
                    ]
                  }
                }
                """);
        assertFalse(result.output().contains("acme"));
        assertEquals(1, result.redactedLines());
    }

    @Test
    void unmaskRestoresTheRealNamesAndKeepsTheJsonValid() throws IOException {
        // SPEC §9 item 3 for this dialect: the round trip has to come back.
        String masked = rewriter.mask(fixture()).output();
        String restored = new dev.threadmine.anon.unmask.Unmasker(engine).unmask(masked).text();

        assertNotNull(Json.parse(restored), "unmasking must not break the document");
        assertTrue(restored.contains("com.acme.payment.LedgerLock"),
                "the lock class must come back: " + restored.substring(0, 200));
        assertTrue(restored.contains("com.acme.gateway.Bootstrap"));
        assertTrue(restored.contains("sync-"), "the route thread name must come back");
    }

    @Test
    void framesGetTheSameTokensAsTheTextDialect() throws IOException {
        // Cross-dialect determinism (SPEC §1): the same vault must give
        // com.acme.payment.LedgerLock one token, whichever dialect it came from.
        String json = rewriter.mask(fixture()).output();

        HotspotRewriter text = new HotspotRewriter(engine, AllowlistMatcher.fromClasspath());
        String textMasked = text.mask(
                "\tat com.acme.payment.PaymentWorker.lambda$settle$1(PaymentWorker.java:64)\n").output();
        String frameToken = textMasked.lines()
                .filter(l -> l.startsWith("\tat "))
                .findFirst().orElseThrow()
                .strip().substring(3).strip();
        String classPart = frameToken.substring(0, frameToken.indexOf('('));

        assertTrue(json.contains(classPart),
                "the JSON dialect must reuse the token the text dialect produced: " + classPart);
    }
}

package dev.threadmine.anon.allowlist;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AllowlistMatcherTest {

    private static final String MINIMAL_JSON = """
            {
              "version": 1,
              "required": {
                "packagePrefixes": ["java.", "org.apache.", "com.sun."],
                "threadNameExact": ["ExactName"],
                "threadNamePrefixes": ["GC ", "C1 CompilerThread", "Reference Handler"],
                "threadNameSuffixes": ["-Acceptor", "-Poller"],
                "threadNameRegexes": ["^http-nio-\\\\d+-exec-\\\\d+$", "^Thread-\\\\d+$"]
              },
              "recommended": {
                "packagePrefixes": ["org.springframework.test.", "com.google.common."]
              }
            }
            """;

    private AllowlistMatcher matcher() {
        return AllowlistMatcher.fromJson(MINIMAL_JSON);
    }

    // --- fromClasspath ----------------------------------------------------

    @Test
    void fromClasspathLoadsTheShippedAllowlist() {
        AllowlistMatcher shipped = AllowlistMatcher.fromClasspath();
        assertNotNull(shipped);
        // entries straight from allowlist/allowlist-v1.json
        assertTrue(shipped.allowsFqcn("java.lang.Thread"));
        assertTrue(shipped.allowsFqcn("org.apache.tomcat.util.threads.TaskThread"));
        assertTrue(shipped.allowsThreadName("http-nio-8080-exec-1"));
        assertTrue(shipped.allowsThreadName("Reference Handler"));
        assertFalse(shipped.allowsFqcn("com.acme.billing.InvoiceService"));
        assertFalse(shipped.allowsThreadName("pgto-worker-3"));
    }

    // --- allowsFqcn -------------------------------------------------------

    @Test
    void allowsFqcnMatchesRequiredPackagePrefixes() {
        assertTrue(matcher().allowsFqcn("java.lang.Thread"));
        assertTrue(matcher().allowsFqcn("org.apache.coyote.http11.Http11InputBuffer"));
        assertTrue(matcher().allowsFqcn("java.util.concurrent"));
        assertFalse(matcher().allowsFqcn("com.acme.payment.LedgerService"));
    }

    @Test
    void allowsFqcnDoesNotMatchOnPartialSegment() {
        // "java." must not admit "javassist..." style lookalikes
        assertFalse(matcher().allowsFqcn("javax.magic.Thing"));
        assertFalse(matcher().allowsFqcn("org.apachefake.X"));
    }

    @Test
    void allowsFqcnIncludesRecommendedTierByDefault() {
        assertTrue(matcher().allowsFqcn("com.google.common.cache.LocalCache"));
    }

    @Test
    void strictModeIgnoresRecommendedTier() {
        AllowlistMatcher strict = matcher().withStrict(true);
        assertFalse(strict.allowsFqcn("com.google.common.cache.LocalCache"));
        assertTrue(strict.allowsFqcn("java.lang.Thread"), "required tier survives strict mode");
    }

    @Test
    void withStrictFalseRestoresRecommendedTier() {
        AllowlistMatcher relaxed = matcher().withStrict(true).withStrict(false);
        assertTrue(relaxed.allowsFqcn("com.google.common.cache.LocalCache"));
    }

    @Test
    void longestPrefixSemanticsWhenPrefixesOverlap() {
        // "org.springframework.test." (recommended) is longer than any required
        // prefix; the longest match decides, and it is an allow either way.
        AllowlistMatcher m = matcher();
        assertTrue(m.allowsFqcn("org.springframework.test.context.TestContext"));
        assertFalse(m.allowsFqcn("org.springframework.core.SpringVersion"),
                "no prefix covers org.springframework.core in this fixture");
    }

    // --- allowsThreadName -------------------------------------------------

    @Test
    void threadNameExactTier() {
        assertTrue(matcher().allowsThreadName("ExactName"));
        assertFalse(matcher().allowsThreadName("ExactName2"));
    }

    @Test
    void threadNamePrefixTier() {
        assertTrue(matcher().allowsThreadName("GC task thread#0 (ParallelGC)"));
        assertTrue(matcher().allowsThreadName("C1 CompilerThread2"));
        assertTrue(matcher().allowsThreadName("Reference Handler"));
        assertFalse(matcher().allowsThreadName("gc-notifier-1"),
                "prefix match is case sensitive: \"GC \" must not admit \"gc-\"");
    }

    @Test
    void threadNameSuffixTier() {
        assertTrue(matcher().allowsThreadName("http-nio-8080-Acceptor"));
        assertTrue(matcher().allowsThreadName("ajp-nio-8009-Poller"));
        assertFalse(matcher().allowsThreadName("my-Acceptor-2"));
    }

    @Test
    void threadNameRegexTier() {
        assertTrue(matcher().allowsThreadName("http-nio-8080-exec-12"));
        assertTrue(matcher().allowsThreadName("Thread-7"));
        assertFalse(matcher().allowsThreadName("Thread-7b"));
        assertFalse(matcher().allowsThreadName("sync-/api/orders?id=99887766"));
    }

    // --- robustness -------------------------------------------------------

    @Test
    void fromJsonRejectsGarbage() {
        assertThrows(RuntimeException.class, () -> AllowlistMatcher.fromJson("not json at all"));
    }

    @Test
    void missingOptionalSectionsAreTreatedAsEmpty() {
        AllowlistMatcher m = AllowlistMatcher.fromJson("""
                {"required": {"packagePrefixes": ["java."]}}
                """);
        assertTrue(m.allowsFqcn("java.lang.String"));
        assertFalse(m.allowsThreadName("anything"));
    }
}

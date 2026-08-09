package dev.threadmine.anon.verify;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The JSON path of {@code verify} must be able to FAIL. A compliance check that
 * cannot reject anything is worse than none: it converts "unverified" into a
 * green tick. Each test here hides one identifier in one field the JDK dumper
 * actually emits and requires the verifier to find it.
 */
class JsonComplianceTest {

    private static final AllowlistLookup ALLOWLIST = new AllowlistLookup() {
        @Override
        public boolean allowsFqcn(String fqcnOrPackage) {
            return fqcnOrPackage.startsWith("java.") || fqcnOrPackage.startsWith("jdk.");
        }

        @Override
        public boolean allowsThreadName(String name) {
            return name.equals("Reference Handler");
        }
    };

    private final ComplianceVerifier verifier = new ComplianceVerifier(ALLOWLIST);

    /** A well-masked dump: tokens everywhere an identifier could live. */
    private static String masked(String threadBody) {
        return """
                {
                  "tmAnon": "# tm-anon v1",
                  "threadDump": {
                    "processId": "1",
                    "threadContainers": [
                      {
                        "container": "<root>",
                        "parent": null,
                        "threads": [
                          {
                            "tid": "1",
                            "name": "t1a2b3xc4d5e",
                            "state": "RUNNABLE",
                            "stack": ["java.base/java.lang.Thread.run(Thread.java:1583)"]%s
                          }
                        ],
                        "threadCount": "1"
                      }
                    ]
                  }
                }
                """.formatted(threadBody);
    }

    private List<VerifyReport.Finding> findings(String masked) {
        return verifier.verify(masked, masked).residualIdentifiers();
    }

    @Test
    void aFullyMaskedJsonDumpPasses() {
        VerifyReport report = verifier.verify(masked(""), masked(""));
        assertEquals(List.of(), report.residualIdentifiers(), "a masked dump must not be flagged");
        assertTrue(report.passed());
    }

    @Test
    void theJsonDialectIsRecognizedAsAThreadDump() {
        assertTrue(ComplianceVerifier.looksLikeThreadDump(masked("")),
                "verify must accept the JSON dialect instead of refusing it as unknown input");
    }

    @Test
    void anUnmaskedThreadNameIsCaught() {
        String leaky = masked("").replace("\"t1a2b3xc4d5e\"", "\"pgto-worker-1\"");
        List<VerifyReport.Finding> findings = findings(leaky);
        assertEquals(1, findings.size(), "the thread name must be reported: " + findings);
        assertEquals("pgto-worker-1", findings.get(0).value());
    }

    @Test
    void anUnmaskedFrameIsCaught() {
        String leaky = masked("").replace("java.base/java.lang.Thread.run(Thread.java:1583)",
                "com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)");
        assertFalse(findings(leaky).isEmpty(), "an application frame must be reported");
    }

    @Test
    void anUnmaskedBlockedOnIsCaught() {
        String leaky = masked(",\n\"blockedOn\": \"com.acme.payment.LedgerLock@1f2e3d\"");
        List<VerifyReport.Finding> findings = findings(leaky);
        assertFalse(findings.isEmpty(), "blockedOn carries a class name and must be checked");
        assertTrue(findings.get(0).value().contains("LedgerLock"), findings.toString());
    }

    @Test
    void anUnmaskedParkBlockerIsCaught() {
        String leaky = masked(",\n\"parkBlocker\": {\"object\": \"com.acme.batch.Gate@ab12\"}");
        assertFalse(findings(leaky).isEmpty(), "parkBlocker.object is nested and must still be checked");
    }

    @Test
    void anUnmaskedMonitorsOwnedLockIsCaught() {
        String leaky = masked(",\n\"monitorsOwned\": [{\"depth\": 2, "
                + "\"locks\": [\"com.acme.stock.StockLatch@99\"]}]");
        assertFalse(findings(leaky).isEmpty(), "monitorsOwned[].locks[] is two levels deep");
    }

    @Test
    void anUnmaskedContainerToStringIsCaught() {
        // The leak that motivated JSON support in the first place.
        String leaky = masked("").replace("\"container\": \"<root>\"",
                "\"container\": \"com.acme.batch.LedgerScope@4f2b1a\"");
        List<VerifyReport.Finding> findings = findings(leaky);
        assertFalse(findings.isEmpty(), "a StructuredTaskScope toString must be reported");
        assertTrue(findings.get(0).value().contains("LedgerScope"), findings.toString());
    }

    @Test
    void anUnmaskedContainerPoolNameIsCaught() {
        String leaky = masked("").replace("\"container\": \"<root>\"",
                "\"container\": \"acme-billing-pool/java.util.concurrent.ThreadPoolExecutor@4f2b1a\"");
        List<VerifyReport.Finding> findings = findings(leaky);
        assertFalse(findings.isEmpty(), "the pool-name half is caller-chosen text and must be checked");
        assertEquals("acme-billing-pool", findings.get(0).value());
    }

    @Test
    void allowlistedNamesAndFramesAreNotFlagged() {
        String clean = masked("").replace("\"t1a2b3xc4d5e\"", "\"Reference Handler\"");
        assertEquals(List.of(), findings(clean));
    }

    @Test
    void redactionMarkersAreNotTreatedAsLeaks() {
        String withRedaction = masked(",\n\"blockedOn\": \"# [tm-anon: redacted]\"");
        assertEquals(List.of(), findings(withRedaction),
                "a redacted value is the fail-closed outcome, not a finding");
    }

    @Test
    void aDroppedStructuralKeyBreaksAnAnchor() {
        String original = masked(",\n\"blockedOn\": \"C1a2b3xc4d5e@1f2e3d\"");
        String stripped = masked("");
        VerifyReport report = verifier.verify(original, stripped);
        assertFalse(report.brokenAnchors().isEmpty(),
                "losing the blockedOn field must break an anchor, not pass silently");
    }
}

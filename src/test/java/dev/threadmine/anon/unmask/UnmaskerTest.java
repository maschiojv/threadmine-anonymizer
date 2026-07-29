package dev.threadmine.anon.unmask;

import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.TokenType;
import dev.threadmine.anon.core.Vault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static dev.threadmine.anon.unmask.VaultFixture.vault;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnmaskerTest {

    private Unmasker unmasker(Path dir, VaultFixture fixture) {
        Vault vault = fixture.writeTo(dir.resolve("test.vault.json"));
        return new Unmasker(new HmacTokenEngine(vault));
    }

    // --- the plain case ---------------------------------------------------

    @Test
    void replacesAStandaloneThreadToken(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault().with("t3f9c1x84d2b", "pgto-worker-1"));

        UnmaskResult result = unmasker.unmask("t3f9c1x84d2b");

        assertEquals("pgto-worker-1", result.text());
        assertEquals(1, result.replacedOccurrences());
        assertEquals(1, result.distinctTokensReplaced());
        assertFalse(result.hasUnresolvedTokens());
    }

    @Test
    void leavesTextWithoutTokensExactlyAsItWas(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault().with("C3f9c1x84d2b", "com.acme.Foo"));

        UnmaskResult result = unmasker.unmask("nothing to see here: java.lang.Thread.State: RUNNABLE\n");

        assertEquals("nothing to see here: java.lang.Thread.State: RUNNABLE\n", result.text());
        assertEquals(0, result.replacedOccurrences());
    }

    // --- canonical value vs. what belongs at the token's position ----------

    @Test
    void aPackageSegmentTokenRestoresOnlyItsOwnSegment(@TempDir Path dir) {
        // The vault stores the canonical value (SPEC §1): the whole path up to
        // the segment. Only the last segment belongs where the token sits.
        Unmasker unmasker = unmasker(dir, vault()
                .with("p11111x11111", "com")
                .with("p22222x22222", "com.acme")
                .with("p33333x33333", "com.acme.billing"));

        assertEquals("com.acme.billing", unmasker.unmask("p11111x11111.p22222x22222.p33333x33333").text());
    }

    @Test
    void aClassTokenRestoresTheSimpleNameNotTheWholeFqcn(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault()
                .with("p11111x11111", "com")
                .with("p22222x22222", "com.acme")
                .with("p33333x33333", "com.acme.billing")
                .with("Caaaaaxbbbbb", "com.acme.billing.InvoiceService"));

        assertEquals("billing.InvoiceService", unmasker.unmask("p33333x33333.Caaaaaxbbbbb").text());
        assertEquals("com.acme.billing.InvoiceService",
                unmasker.unmask("p11111x11111.p22222x22222.p33333x33333.Caaaaaxbbbbb").text());
    }

    @Test
    void anInnerClassTokenRestoresOnlyTheInnerPart(@TempDir Path dir) {
        // SPEC §1: each $-separated part is its own class token, canonically
        // named with the whole outer$Inner chain.
        Unmasker unmasker = unmasker(dir, vault()
                .with("Caaaaaxbbbbb", "com.acme.order.Outer")
                .with("Cbbbbbxccccc", "com.acme.order.Outer$Inner")
                .with("Ccccccxddddd", "com.acme.order.Outer$Inner$1"));

        assertEquals("Outer$Inner$1",
                unmasker.unmask("Caaaaaxbbbbb$Cbbbbbxccccc$Ccccccxddddd").text());
    }

    @Test
    void aMethodTokenRestoresOnlyTheMethodName(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault()
                .with("Caaaaaxbbbbb", "com.acme.billing.InvoiceService")
                .with("mcccccxddddd", "com.acme.billing.InvoiceService#issue"));

        assertEquals("InvoiceService.issue", unmasker.unmask("Caaaaaxbbbbb.mcccccxddddd").text());
    }

    @Test
    void aThreadTokenRestoresTheWholeName(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault().with("t1a2b3xc4d5e", "com.acme.scheduler.tick"));

        assertEquals("com.acme.scheduler.tick", unmasker.unmask("t1a2b3xc4d5e").text());
    }

    @Test
    void rebuildsAWholeStackFrameIncludingTheSourceFile(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault()
                .with("p11111x11111", "com")
                .with("p22222x22222", "com.acme")
                .with("p33333x33333", "com.acme.payment")
                .with("Caaaaaxbbbbb", "com.acme.payment.LedgerService")
                .with("mcccccxddddd", "com.acme.payment.LedgerService#applyEntry")
                .with("Ceeeeexfffff", "com.acme.payment.LedgerService"));

        UnmaskResult result = unmasker.unmask(
                "\tat p11111x11111.p22222x22222.p33333x33333.Caaaaaxbbbbb.mcccccxddddd(Ceeeeexfffff.java:88)");

        assertEquals("\tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)", result.text());
    }

    // --- ThreadMine export JSON -------------------------------------------

    @Test
    void unmasksTheThreadMineExportJsonShapeInPlace(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault()
                .with("t1a2b3xc4d5e", "pgto-worker-1")
                .with("t9f8e7xd6c5b", "pgto-worker-2")
                .with("p11111x11111", "com")
                .with("p22222x22222", "com.acme")
                .with("p33333x33333", "com.acme.payment")
                .with("Caaaaaxbbbbb", "com.acme.payment.LedgerService")
                .with("mcccccxddddd", "com.acme.payment.LedgerService#applyEntry"));

        String export = """
                {
                  "metadados": { "versao": 1, "geradoEm": "2026-07-24T12:00:00Z" },
                  "sumario": { "healthScore": 42, "threads": 2 },
                  "problemas": [
                    {
                      "tipo": "LOCK_CONTENTION",
                      "descricao": "Thread t1a2b3xc4d5e is blocked on a monitor held by t9f8e7xd6c5b; the \
                contention point is Caaaaaxbbbbb.mcccccxddddd, reached on every request."
                    }
                  ],
                  "threads": [
                    {
                      "nome": "t1a2b3xc4d5e",
                      "estado": "BLOCKED",
                      "stackFrames": [
                        "at p11111x11111.p22222x22222.p33333x33333.Caaaaaxbbbbb.mcccccxddddd(Caaaaaxbbbbb.java:88)",
                        "at java.lang.Thread.run(java.base@17.0.8/Thread.java:833)"
                      ]
                    }
                  ]
                }
                """;

        String text = unmasker.unmask(export).text();

        assertTrue(text.contains("\"nome\": \"pgto-worker-1\""), text);
        assertTrue(text.contains("Thread pgto-worker-1 is blocked"), text);
        assertTrue(text.contains("held by pgto-worker-2;"), text);
        assertTrue(text.contains("contention point is LedgerService.applyEntry,"), text);
        assertTrue(text.contains("\"at com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)\""), text);
        assertTrue(text.contains("at java.lang.Thread.run(java.base@17.0.8/Thread.java:833)"),
                "allowlisted frames were never tokenized and must survive untouched");
        assertTrue(text.contains("\"healthScore\": 42"), "numbers must not be disturbed");
    }

    // --- Vein prose --------------------------------------------------------

    @Test
    void unmasksTokensSittingMidSentenceNextToPunctuation(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault()
                .with("Caaaaaxbbbbb", "com.acme.payment.LedgerService")
                .with("t1a2b3xc4d5e", "pgto-worker-1"));

        String prose = "The bottleneck is Caaaaaxbbbbb, reached from t1a2b3xc4d5e. "
                + "Consider whether Caaaaaxbbbbb needs a coarse lock at all "
                + "(t1a2b3xc4d5e; Caaaaaxbbbbb) - see \"t1a2b3xc4d5e\".";

        UnmaskResult result = unmasker.unmask(prose);

        assertEquals("The bottleneck is LedgerService, reached from pgto-worker-1. "
                + "Consider whether LedgerService needs a coarse lock at all "
                + "(pgto-worker-1; LedgerService) - see \"pgto-worker-1\".", result.text());
        assertEquals(6, result.replacedOccurrences());
        assertEquals(2, result.distinctTokensReplaced());
    }

    // --- token grammar edge cases -----------------------------------------

    @Test
    void resolvesTheRouteMarkerSuffixBackToTheFullThreadName(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir,
                vault().with("t7c1d2xe3f4a", "sync-tenant-acme/api/orders?id=99887766"));

        UnmaskResult result = unmasker.unmask("thread \"t7c1d2xe3f4a/q\" was stuck");

        assertEquals("thread \"sync-tenant-acme/api/orders?id=99887766\" was stuck", result.text());
        assertEquals(1, result.replacedOccurrences());
    }

    @Test
    void resolvesTheExtendedCollisionForm(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault()
                .with("t9e2a4f1xb7f3190", "billing-worker")
                .with("t9e2a1xb7f31", "shipping-worker"));

        UnmaskResult result = unmasker.unmask("t9e2a4f1xb7f3190 and t9e2a1xb7f31 are different threads");

        assertEquals("billing-worker and shipping-worker are different threads", result.text());
        assertEquals(2, result.replacedOccurrences());
    }

    @Test
    void resolvesTheExtendedFormEvenWithTheRouteMarker(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault().with("t9e2a4f1xb7f3190", "orders/api/v1?id=7"));

        assertEquals("orders/api/v1?id=7", unmasker.unmask("t9e2a4f1xb7f3190/q").text());
    }

    @Test
    void treatsDollarsAndBackslashesInTheOriginalAsLiteralText(@TempDir Path dir) {
        // A raw appendReplacement would read $1 as a group reference and \ as
        // an escape; both appear in real names.
        Unmasker unmasker = unmasker(dir, vault()
                .with("t1a2b3xc4d5e", "pool-$1-thread-7")
                .with("t2b3c4xd5e6f", "win\\path\\worker-1")
                .with("Caaaaaxbbbbb", "com.acme.order.Outer$$Lambda$42"));

        UnmaskResult result = unmasker.unmask("t1a2b3xc4d5e / t2b3c4xd5e6f / Caaaaaxbbbbb");

        assertEquals("pool-$1-thread-7 / win\\path\\worker-1 / 42", result.text());
    }

    // --- unknown tokens ----------------------------------------------------

    @Test
    void keepsUnknownTokensVerbatimAndReportsThem(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault().with("t1a2b3xc4d5e", "pgto-worker-1"));

        UnmaskResult result = unmasker.unmask("t1a2b3xc4d5e calls C00000x11111 twice: C00000x11111");

        assertEquals("pgto-worker-1 calls C00000x11111 twice: C00000x11111", result.text());
        assertEquals(1, result.replacedOccurrences());
        assertEquals(List.of("C00000x11111"), result.unresolvedTokens());
        assertEquals(2, result.unresolvedOccurrences());
        assertTrue(result.hasUnresolvedTokens());
    }

    @Test
    void reportsAnUnknownRouteTokenAsItAppearsInTheText(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault().with("Caaaaaxbbbbb", "com.acme.Known"));

        UnmaskResult result = unmasker.unmask("t00000x11111/q");

        assertEquals("t00000x11111/q", result.text());
        assertEquals(List.of("t00000x11111/q"), result.unresolvedTokens());
    }

    // --- idempotence -------------------------------------------------------

    @Test
    void runningUnmaskTwiceChangesNothingTheSecondTime(@TempDir Path dir) {
        Unmasker unmasker = unmasker(dir, vault()
                .with("Caaaaaxbbbbb", "com.acme.payment.LedgerService")
                .with("t1a2b3xc4d5e", "pgto-worker-1"));

        String once = unmasker.unmask("at Caaaaaxbbbbb in t1a2b3xc4d5e").text();
        UnmaskResult twice = unmasker.unmask(once);

        assertEquals(once, twice.text());
        assertEquals(0, twice.replacedOccurrences());
        assertFalse(twice.hasUnresolvedTokens());
    }

    // --- round trip against the real engine -------------------------------

    @Test
    void undoesWhatTheRealTokenEngineProduced(@TempDir Path dir) {
        Vault vault = Vault.create(dir.resolve("roundtrip.vault.json"));
        TokenEngine engine = new HmacTokenEngine(vault);
        String packageToken = engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.acme.billing");
        String classToken = engine.tokenize(TokenType.CLASS_NAME, "com.acme.billing.InvoiceService");
        String methodToken = engine.tokenize(TokenType.METHOD_NAME, "com.acme.billing.InvoiceService#issue");
        String threadToken = engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");

        UnmaskResult result = new Unmasker(engine).unmask("\"" + threadToken + "-3\" ran "
                + packageToken + "." + classToken + "." + methodToken);

        assertEquals("\"pgto-worker-3\" ran billing.InvoiceService.issue", result.text());
    }
}

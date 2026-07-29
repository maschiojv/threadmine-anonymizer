package dev.threadmine.anon.verify;

import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.TokenType;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.verify.VerifyReport.AnchorCheck;
import dev.threadmine.anon.verify.VerifyReport.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ComplianceVerifierTest {

    private final ComplianceVerifier verifier =
            new ComplianceVerifier(FakeAllowlistMatcher.threadMineDefaults());

    private static final String ORIGINAL = """
            2026-07-24 09:31:47
            Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode, sharing):

            Threads class SMR info:
            _java_thread_list=0x00006000021c4d20, length=2, elements={
            0x00007fb2a3809200, 0x00007fb2a3810800
            }

            "pgto-worker-1" #15 prio=5 os_prio=31 cpu=4211.03ms elapsed=410.55s tid=0x00007fb2a3813200 nid=0x5203 runnable
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:95)
            \t- locked <0x000000061f8a2b40> (a com.acme.payment.LedgerLock)
            \tat java.lang.Thread.run(java.base@17.0.8/Thread.java:833)

               Locked ownable synchronizers:
            \t- None

            "http-nio-8080-exec-1" #18 daemon prio=5 os_prio=31 tid=0x00007fb2a3874c00 nid=0x5803 runnable
               java.lang.Thread.State: RUNNABLE
            \tat org.apache.tomcat.util.threads.TaskQueue.poll(TaskQueue.java:99)

            JNI global refs: 21, weak refs: 0
            """;

    /** What a correct mask run produces for {@link #ORIGINAL}. */
    private static final String MASKED = """
            # tm-anon v1
            2026-07-24 09:31:47
            Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode, sharing):

            # [tm-anon: stripped]

            "t1a2b3xc4d5e-1" #15 prio=5 os_prio=31 cpu=4211.03ms elapsed=410.55s tid=0x00007fb2a3813200 nid=0x5203 runnable
               java.lang.Thread.State: RUNNABLE
            \tat p11111x11111.p22222x22222.p33333x33333.Caaaaaxbbbbb.mcccccxddddd(Caaaaaxbbbbb.java:95)
            \t- locked <0x000000061f8a2b40> (a p11111x11111.p22222x22222.p33333x33333.Cdddddxeeeee)
            \tat java.lang.Thread.run(java.base@17.0.8/Thread.java:833)

            # [tm-anon: stripped]

            "http-nio-8080-exec-1" #18 daemon prio=5 os_prio=31 tid=0x00007fb2a3874c00 nid=0x5803 runnable
               java.lang.Thread.State: RUNNABLE
            \tat org.apache.tomcat.util.threads.TaskQueue.poll(TaskQueue.java:99)

            # [tm-anon: stripped]
            """;

    // --- the happy path ----------------------------------------------------

    @Test
    void aCorrectlyMaskedDumpPasses() {
        VerifyReport report = verifier.verify(ORIGINAL, MASKED);

        assertEquals(List.of(), report.residualIdentifiers(), "nothing identifiable may be left");
        assertEquals(List.of(), report.brokenAnchors());
        assertTrue(report.counts().allMatch());
        assertTrue(report.passed());
    }

    @Test
    void countsBothSidesAndReportsTheMaskingMarkers() {
        VerifyReport report = verifier.verify(ORIGINAL, MASKED);

        assertEquals(2, report.counts().originalThreads());
        assertEquals(2, report.counts().maskedThreads());
        assertEquals(3, report.counts().originalFrames());
        assertEquals(3, report.counts().maskedFrames());
        assertEquals(3, report.strippedLines());
        assertEquals(0, report.redactedLines());
        assertTrue(report.counts().tokensInMasked() > 0);
    }

    @Test
    void anchorsAreCountedOnBothSides() {
        VerifyReport report = verifier.verify(ORIGINAL, MASKED);

        AnchorCheck state = report.anchors().stream()
                .filter(a -> a.marker().equals("java.lang.Thread.State:")).findFirst().orElseThrow();
        assertEquals(2, state.inOriginal());
        assertEquals(2, state.inMasked());
        assertTrue(report.anchors().stream().anyMatch(a -> a.marker().equals("Full thread dump")));
        assertTrue(report.anchors().stream().anyMatch(a -> a.marker().equals("- locked")));
        assertTrue(report.anchors().stream().noneMatch(a -> a.marker().equals("<pinned:")),
                "anchors absent from both sides are noise, not findings");
    }

    // --- (a) residual identifiers -----------------------------------------

    @Test
    void catchesAnApplicationClassThatSurvivedInAFrame() {
        String leaky = MASKED.replace(
                "\tat p11111x11111.p22222x22222.p33333x33333.Caaaaaxbbbbb.mcccccxddddd(Caaaaaxbbbbb.java:95)",
                "\tat com.acme.payment.LedgerService.applyEntry(Caaaaaxbbbbb.java:95)");

        VerifyReport report = verifier.verify(ORIGINAL, leaky);

        assertFalse(report.passed());
        Finding finding = report.residualIdentifiers().get(0);
        assertEquals(Finding.Kind.FRAME_CLASS, finding.kind());
        assertEquals("com.acme.payment.LedgerService.applyEntry", finding.value());
        assertTrue(finding.line() > 0, "a finding must say where to look");
    }

    @Test
    void catchesASourceFileThatSurvivedInAnOtherwiseMaskedFrame() {
        String leaky = MASKED.replace("(Caaaaaxbbbbb.java:95)", "(LedgerService.java:95)");

        VerifyReport report = verifier.verify(ORIGINAL, leaky);

        assertFalse(report.passed());
        assertEquals(Finding.Kind.SOURCE_FILE, report.residualIdentifiers().get(0).kind());
        assertEquals("LedgerService.java", report.residualIdentifiers().get(0).value());
    }

    @Test
    void catchesAThreadNameThatSurvived() {
        String leaky = MASKED.replace("\"t1a2b3xc4d5e-1\"", "\"pgto-worker-1\"");

        VerifyReport report = verifier.verify(ORIGINAL, leaky);

        assertFalse(report.passed());
        assertEquals(Finding.Kind.THREAD_NAME, report.residualIdentifiers().get(0).kind());
        assertEquals("pgto-worker-1", report.residualIdentifiers().get(0).value());
    }

    @Test
    void catchesALockClassThatSurvived() {
        String leaky = MASKED.replace("(a p11111x11111.p22222x22222.p33333x33333.Cdddddxeeeee)",
                "(a com.acme.payment.LedgerLock)");

        VerifyReport report = verifier.verify(ORIGINAL, leaky);

        assertFalse(report.passed());
        assertEquals(Finding.Kind.LOCK_CLASS, report.residualIdentifiers().get(0).kind());
        assertEquals("com.acme.payment.LedgerLock", report.residualIdentifiers().get(0).value());
    }

    @Test
    void catchesAClassLeakingThroughTheThreadMXBeanAtHashForm() {
        String original = """
                Full thread dump Java HotSpot(TM) 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "pgto-worker-1" Id=31 BLOCKED on com.acme.payment.LedgerLock@1f2e3d
                \tat app//com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)
                """;
        String masked = """
                # tm-anon v1
                Full thread dump Java HotSpot(TM) 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "t1a2b3xc4d5e-1" Id=31 BLOCKED on com.acme.payment.LedgerLock@1f2e3d
                \tat app//p11111x11111.Caaaaaxbbbbb.mcccccxddddd(Caaaaaxbbbbb.java:88)
                """;

        VerifyReport report = verifier.verify(original, masked);

        assertFalse(report.passed());
        assertEquals(List.of("com.acme.payment.LedgerLock"),
                report.residualIdentifiers().stream().map(Finding::value).toList());
    }

    @Test
    void catchesLeaksInJcmdTextFramesWhichCarryNoAtKeyword() {
        // jcmd Thread.dump_to_file -format=text writes frames with no "at ".
        // Missing them would make verify sign off on a fully readable dump.
        String original = """
                #30 "pgto-worker-1" BLOCKED
                      com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)
                      java.base/java.lang.Thread.run(Thread.java:1583)
                """;
        String masked = """
                # tm-anon v1
                #30 "t1a2b3xc4d5e-1" BLOCKED
                      com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)
                      java.base/java.lang.Thread.run(Thread.java:1583)
                """;

        VerifyReport report = verifier.verify(original, masked);

        assertFalse(report.passed());
        assertEquals(2, report.counts().maskedFrames(), "bare frames must be counted as frames");
        assertTrue(report.residualIdentifiers().stream()
                        .anyMatch(f -> f.value().equals("com.acme.payment.LedgerService.applyEntry")),
                report.residualIdentifiers().toString());
    }

    @Test
    void acceptsACorrectlyMaskedJcmdTextDump() {
        String masked = """
                # tm-anon v1
                #30 "t1a2b3xc4d5e-1" BLOCKED
                      p11111x11111.Caaaaaxbbbbb.mcccccxddddd(Caaaaaxbbbbb.java:88)
                      java.base/java.lang.Thread.run(Thread.java:1583)
                """;

        VerifyReport report = verifier.verify(masked, masked);

        assertEquals(List.of(), report.residualIdentifiers(), report.residualIdentifiers().toString());
        assertTrue(report.passed());
    }

    @Test
    void acceptsPublicInfrastructureLeftVerbatim() {
        // The whole point of the allowlist: these frames and names are not secrets.
        String original = """
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "Reference Handler" #2 daemon prio=10 tid=0x1 nid=0x2 runnable
                   java.lang.Thread.State: RUNNABLE
                \tat java.lang.ref.Reference.waitForReferencePendingList(java.base@21.0.3/Native Method)
                \tat app//org.springframework.boot.SpringApplication.run(SpringApplication.java:334)
                \tat java.base@21.0.3/java.lang.Thread.run(Thread.java:1583)
                """;

        VerifyReport report = verifier.verify(original, "# tm-anon v1\n" + original);

        assertEquals(List.of(), report.residualIdentifiers());
        assertTrue(report.passed());
    }

    @Test
    void acceptsMaskedLambdaInnerAndProxyScaffolding() {
        String masked = """
                # tm-anon v1
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "t1a2b3xc4d5e" #15 prio=5 tid=0x1 nid=0x2 runnable
                   java.lang.Thread.State: RUNNABLE
                \tat p11111x11111.Caaaaaxbbbbb$Cbbbbbxccccc.lambda$mcccccxddddd$0(Caaaaaxbbbbb.java:41)
                \tat p11111x11111.Caaaaaxbbbbb$$Lambda$14/0x00007f1c2a3b4c.mcccccxddddd(Unknown Source)
                \tat p11111x11111.Cbbbbbxccccc.<init>(Cbbbbbxccccc.java:12)
                """;

        VerifyReport report = verifier.verify(masked, masked);

        assertEquals(List.of(), report.residualIdentifiers(), report.residualIdentifiers().toString());
    }

    @Test
    void acceptsEveryTokenFormWhereAThreadNameCanAppear() {
        String masked = """
                # tm-anon v1
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "t1a2b3xc4d5e" #15 prio=5 tid=0x1 nid=0x2 runnable
                   java.lang.Thread.State: RUNNABLE

                "t1a2b3xc4d5e-7" #16 prio=5 tid=0x2 nid=0x3 runnable
                   java.lang.Thread.State: RUNNABLE

                "t7c1d2xe3f4a/q" #17 prio=5 tid=0x3 nid=0x4 runnable
                   java.lang.Thread.State: RUNNABLE

                "t9e2a4f1xb7f3190" #18 prio=5 tid=0x4 nid=0x5 runnable
                   java.lang.Thread.State: RUNNABLE

                "" #19 virtual prio=5 tid=0x5 nid=0x0 runnable
                   java.lang.Thread.State: RUNNABLE
                      <virtual thread is mounted on carrier thread "ForkJoinPool-1-worker-1">
                """;

        VerifyReport report = verifier.verify(masked, masked);

        assertEquals(List.of(), report.residualIdentifiers(), report.residualIdentifiers().toString());
    }

    @Test
    void reallyAsksTheAllowlistInsteadOfHardcodingJavaPackages() {
        ComplianceVerifier paranoid = new ComplianceVerifier(FakeAllowlistMatcher.denyingEverything());

        VerifyReport report = paranoid.verify(ORIGINAL, MASKED);

        assertFalse(report.passed());
        assertTrue(report.residualIdentifiers().stream()
                        .anyMatch(f -> f.value().startsWith("java.lang.Thread")),
                "with an empty allowlist even java.lang has to be reported: "
                        + report.residualIdentifiers());
    }

    @Test
    void followsTheStrictTierDecisionOfTheAllowlist() {
        String dump = """
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "t1a2b3xc4d5e" #15 prio=5 tid=0x1 nid=0x2 runnable
                   java.lang.Thread.State: RUNNABLE
                \tat com.fasterxml.jackson.databind.ObjectMapper.readValue(ObjectMapper.java:3822)
                """;

        assertTrue(new ComplianceVerifier(FakeAllowlistMatcher.threadMineDefaults())
                .verify(dump, dump).passed(), "recommended tier is preserved by default");
        assertFalse(new ComplianceVerifier(FakeAllowlistMatcher.threadMineDefaults().withStrict(true))
                .verify(dump, dump).passed(), "under --strict the same frame must be tokenized");
    }

    // --- (b) structural anchors -------------------------------------------

    @Test
    void failsWhenTheFormatAnchorLineIsGone() {
        String broken = MASKED.replace("Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode, sharing):",
                "# [tm-anon: redacted]");

        VerifyReport report = verifier.verify(ORIGINAL, broken);

        assertFalse(report.passed());
        assertEquals(List.of("Full thread dump"), report.brokenAnchors().stream()
                .map(AnchorCheck::marker).toList());
        assertEquals(1, report.redactedLines());
    }

    @Test
    void failsWhenAThreadStateLineIsLost() {
        String broken = MASKED.replaceFirst("   java\\.lang\\.Thread\\.State: RUNNABLE\n", "");

        VerifyReport report = verifier.verify(ORIGINAL, broken);

        assertFalse(report.passed());
        assertTrue(report.brokenAnchors().stream().anyMatch(a -> a.marker().equals("java.lang.Thread.State:")));
    }

    @Test
    void failsWhenALoomMarkerIsLost() {
        String original = """
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "" #21 virtual prio=5 tid=0x1 nid=0x0 waiting for monitor entry
                   java.lang.Thread.State: BLOCKED (on object monitor)
                      <pinned: synchronized>
                      <virtual thread is mounted on carrier thread "ForkJoinPool-1-worker-1">
                """;
        String masked = original.replace("      <pinned: synchronized>\n", "");

        VerifyReport report = verifier.verify(original, masked);

        assertFalse(report.passed());
        assertTrue(report.brokenAnchors().stream().anyMatch(a -> a.marker().equals("<pinned:")));
    }

    @Test
    void failsWhenADeadlockBlockIsLost() {
        String original = """
                Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode):

                "pgto-worker-1" #14 prio=5 tid=0x1 nid=0x2 waiting for monitor entry
                   java.lang.Thread.State: BLOCKED (on object monitor)

                Found one Java-level deadlock:
                =============================
                "pgto-worker-1":
                  waiting to lock monitor 0x00007fa86800fe00 (object 0x000000061fcc9b90, a com.acme.stock.StockLatch),
                  which is held by "pgto-worker-2"

                Java stack information for the threads listed above:
                ===================================================
                """;
        String masked = """
                # tm-anon v1
                Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode):

                "t1a2b3xc4d5e-1" #14 prio=5 tid=0x1 nid=0x2 waiting for monitor entry
                   java.lang.Thread.State: BLOCKED (on object monitor)

                # [tm-anon: redacted]
                =============================
                "t1a2b3xc4d5e-1":
                  waiting to lock monitor 0x00007fa86800fe00 (object 0x000000061fcc9b90, a p11111x11111.Caaaaaxbbbbb),
                  which is held by "t1a2b3xc4d5e-2"

                # [tm-anon: redacted]
                ===================================================
                """;

        VerifyReport report = verifier.verify(original, masked);

        assertFalse(report.passed());
        assertEquals(List.of("Java-level deadlock:", "Java stack information for the threads listed above:"),
                report.brokenAnchors().stream().map(AnchorCheck::marker).toList());
    }

    @Test
    void aCorrectlyMaskedDeadlockBlockPasses() {
        String original = """
                Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode):

                "pgto-worker-1" #14 prio=5 tid=0x1 nid=0x2 waiting for monitor entry
                   java.lang.Thread.State: BLOCKED (on object monitor)

                Found one Java-level deadlock:
                =============================
                "pgto-worker-1":
                  waiting to lock monitor 0x00007fa86800fe00 (object 0x000000061fcc9b90, a com.acme.stock.StockLatch),
                  which is held by "pgto-worker-2"
                """;
        String masked = """
                # tm-anon v1
                Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode):

                "t1a2b3xc4d5e-1" #14 prio=5 tid=0x1 nid=0x2 waiting for monitor entry
                   java.lang.Thread.State: BLOCKED (on object monitor)

                Found one Java-level deadlock:
                =============================
                "t1a2b3xc4d5e-1":
                  waiting to lock monitor 0x00007fa86800fe00 (object 0x000000061fcc9b90, a p11111x11111.Caaaaaxbbbbb),
                  which is held by "t1a2b3xc4d5e-2"
                """;

        VerifyReport report = verifier.verify(original, masked);

        assertEquals(List.of(), report.residualIdentifiers(), report.residualIdentifiers().toString());
        assertTrue(report.passed());
        assertEquals(1, report.counts().maskedThreads(),
                "the quoted names inside a deadlock block are back-references, not extra threads");
    }

    // --- (c) counts --------------------------------------------------------

    @Test
    void failsWhenAThreadDisappeared() {
        String broken = MASKED.replace("""
                "http-nio-8080-exec-1" #18 daemon prio=5 os_prio=31 tid=0x00007fb2a3874c00 nid=0x5803 runnable
                """, "");

        VerifyReport report = verifier.verify(ORIGINAL, broken);

        assertFalse(report.passed());
        assertFalse(report.counts().threadsMatch());
    }

    @Test
    void failsWhenAFrameDisappeared() {
        String broken = MASKED.replace(
                "\tat java.lang.Thread.run(java.base@17.0.8/Thread.java:833)\n", "");

        VerifyReport report = verifier.verify(ORIGINAL, broken);

        assertFalse(report.passed());
        assertFalse(report.counts().framesMatch());
    }

    @Test
    void failsWhenABlankLineWasRemoved() {
        // Blank lines delimit threads: dropping one merges two threads for
        // every parser downstream, without changing a single visible name.
        String broken = MASKED.replaceFirst("\n\n", "\n");

        VerifyReport report = verifier.verify(ORIGINAL, broken);

        assertFalse(report.passed());
        assertFalse(report.counts().blankLinesMatch());
    }

    // --- vault cross-check -------------------------------------------------

    @Test
    void reportsTokensThatTheGivenVaultCannotReverse(@TempDir Path dir) {
        Vault vault = Vault.create(dir.resolve("other.vault.json"));
        TokenEngine engine = new HmacTokenEngine(vault);
        engine.tokenize(TokenType.THREAD_NAME, "some-other-thread");

        VerifyReport report = verifier.verify(ORIGINAL, MASKED, engine);

        assertFalse(report.unknownTokens().isEmpty(),
                "MASKED was not produced by this vault, so its tokens are unknown");
        assertTrue(report.passed(), "an unrelated vault is a warning, not a compliance failure");
    }

    @Test
    void reportsNoUnknownTokensWhenNoVaultIsSupplied() {
        assertEquals(List.of(), verifier.verify(ORIGINAL, MASKED).unknownTokens());
    }

    // --- format detection (exit 2) ----------------------------------------

    @Test
    void recognizesAThreadDumpByItsHeaderOrByItsThreads() {
        assertTrue(ComplianceVerifier.looksLikeThreadDump(ORIGINAL));
        assertTrue(ComplianceVerifier.looksLikeThreadDump("""
                "pgto-worker-1" #31 prio=5 tid=0x1000 nid=0x1000 waiting for monitor entry
                   java.lang.Thread.State: BLOCKED (on object monitor)
                """), "a dump without a header is still a dump");
        assertTrue(ComplianceVerifier.looksLikeThreadDump("""
                #31 "pgto-worker-1" BLOCKED
                \tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)
                """), "jcmd text format");
    }

    @Test
    void refusesTextThatIsNotAThreadDump() {
        assertFalse(ComplianceVerifier.looksLikeThreadDump("{\"hello\": \"world\"}"));
        assertFalse(ComplianceVerifier.looksLikeThreadDump(""));
    }
}

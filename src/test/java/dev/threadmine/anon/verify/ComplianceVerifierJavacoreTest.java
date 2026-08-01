package dev.threadmine.anon.verify;

import dev.threadmine.anon.verify.VerifyReport.Finding;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SPEC §5-B.9: {@code verify} must fail (exit 4) when a forbidden javacore
 * section survives in the masked file or when {@code 1TIFILENAME} still has
 * content — plus the general checks (residual identifiers, counts) applied to
 * the javacore shape (§5-B.4/§5-B.7).
 */
class ComplianceVerifierJavacoreTest {

    private static final String ORIGINAL = String.join("\n",
            "0SECTION       TITLE subcomponent dump routine",
            "1TISIGINFO     Dump Event \"user\" (00004000) received",
            "1TIDATETIME    Date: 2026/02/10 at 09:30:11:224 (UTC)",
            "1TIFILENAME    Javacore filename:    /opt/corp/payments/javacore.txt",
            "0SECTION       ENVINFO subcomponent dump routine",
            "1CICMDLINE     /opt/java/bin/java -Dcorp.db.password=Hunter2! -jar corp.jar",
            "0SECTION       THREADS subcomponent dump routine",
            "1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)",
            "3XMTHREADINFO      \"pgto-worker-1\" J9VMThread:0x0000000000ABC100, state:B, prio=5",
            "3XMCPUTIME               CPU usage total: 12.470131900 secs, current category=\"Application\"",
            "3XMTHREADBLOCK     Blocked on: com/acme/payment/WalletService@0x00000000E00A2C48 Owned by: \"pgto-worker-2\" (J9VMThread:0x0000000000ABD200)",
            "4XESTACKTRACE                at com/acme/payment/WalletService.debit(WalletService.java:88(Compiled Code))",
            "4XESTACKTRACE                at java/lang/Thread.run(Thread.java:857)",
            "3XMTHREADINFO      \"pgto-worker-2\" J9VMThread:0x0000000000ABD200, state:R, prio=5",
            "4XESTACKTRACE                at java/util/concurrent/LinkedBlockingQueue.take(LinkedBlockingQueue.java:435)",
            "");

    /** Hand-built compliant mask of ORIGINAL: tokens are shaped, not vault-derived. */
    private static final String MASKED = String.join("\n",
            "# tm-anon v1",
            "0SECTION       TITLE subcomponent dump routine",
            "1TISIGINFO     Dump Event \"user\" (00004000) received",
            "1TIDATETIME    Date: 2026/02/10 at 09:30:11:224 (UTC)",
            "1TIFILENAME    [tm-anon: redacted]",
            "# [tm-anon: stripped section ENVINFO]",
            "0SECTION       THREADS subcomponent dump routine",
            "1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)",
            "3XMTHREADINFO      \"t11111x22222-1\" J9VMThread:0x0000000000ABC100, state:B, prio=5",
            "3XMCPUTIME               CPU usage total: 12.470131900 secs, current category=\"Application\"",
            "3XMTHREADBLOCK     Blocked on: paaaaaxbbbbb/pcccccxddddd/peeeeexfffff/C11111x22222@0x00000000E00A2C48 Owned by: \"t11111x22222-2\" (J9VMThread:0x0000000000ABD200)",
            "4XESTACKTRACE                at paaaaaxbbbbb/pcccccxddddd/peeeeexfffff/C11111x22222.m33333x44444(C11111x22222.java:88(Compiled Code))",
            "4XESTACKTRACE                at java/lang/Thread.run(Thread.java:857)",
            "3XMTHREADINFO      \"t11111x22222-2\" J9VMThread:0x0000000000ABD200, state:R, prio=5",
            "4XESTACKTRACE                at java/util/concurrent/LinkedBlockingQueue.take(LinkedBlockingQueue.java:435)",
            "");

    private final ComplianceVerifier verifier =
            new ComplianceVerifier(FakeAllowlistMatcher.threadMineDefaults());

    @Test
    void javacoreIsRecognizedAsAThreadDump() {
        assertTrue(ComplianceVerifier.looksLikeThreadDump(ORIGINAL),
                "3XMTHREADINFO headers must count as threads");
    }

    @Test
    void compliantMaskedJavacorePasses() {
        VerifyReport report = verifier.verify(ORIGINAL, MASKED);
        assertEquals(java.util.List.of(), report.residualIdentifiers());
        assertTrue(report.counts().allMatch(), report.counts().toString());
        assertTrue(report.passed());
    }

    @Test
    void javacoreThreadsAndFramesAreCounted() {
        VerifyReport report = verifier.verify(ORIGINAL, MASKED);
        assertEquals(2, report.counts().originalThreads());
        assertEquals(2, report.counts().maskedThreads());
        assertEquals(3, report.counts().originalFrames());
        assertEquals(3, report.counts().maskedFrames());
    }

    @Test
    void survivingForbiddenSectionLineFailsVerify() {
        String leaked = MASKED.replace("# [tm-anon: stripped section ENVINFO]",
                "1CICMDLINE     /opt/java/bin/java -Dcorp.db.password=Hunter2! -jar corp.jar");
        VerifyReport report = verifier.verify(ORIGINAL, leaked);
        assertFalse(report.passed(), "a surviving CI line is a leak (SPEC 5-B.9)");
        assertTrue(report.residualIdentifiers().stream()
                        .anyMatch(f -> f.kind() == Finding.Kind.FORBIDDEN_SECTION),
                report.residualIdentifiers().toString());
    }

    @Test
    void everyForbiddenFamilyIsFlagged() {
        for (String line : new String[] {
                "1CISYSCP       Sys Classpath: /opt/app.jar",
                "2LKMONINUSE      sys_mon_t:0x00007F30C4041D08",
                "3CLTEXTCLASS   		com/acme/payment/WalletService(0x00000000012A5100)",
                "1DCHEADEREYE   Header eye catcher  DCST",
                "2DGTRCTYPE       Trace: Internal",
                "1STHEAPFREE    Bytes of Heap Space Free: 9a1c40",
                "1XEJITINIT     JIT is initialized"}) {
            VerifyReport report = verifier.verify(ORIGINAL, MASKED + line + "\n");
            assertFalse(report.passed(), "must fail on surviving: " + line);
            assertTrue(report.residualIdentifiers().stream()
                            .anyMatch(f -> f.kind() == Finding.Kind.FORBIDDEN_SECTION),
                    "expected FORBIDDEN_SECTION for: " + line);
        }
    }

    @Test
    void stackTraceTokensAreNotMistakenForTheForbiddenXeSection() {
        // 4XESTACKTRACE and 4XENATIVESTACK are XE-family tokens that live in
        // the THREADS section; only depth-1 XE tokens mark the XE section.
        VerifyReport report = verifier.verify(ORIGINAL, MASKED);
        assertTrue(report.residualIdentifiers().stream()
                .noneMatch(f -> f.kind() == Finding.Kind.FORBIDDEN_SECTION));
    }

    @Test
    void filenameWithContentFailsVerify() {
        String leaked = MASKED.replace("1TIFILENAME    [tm-anon: redacted]",
                "1TIFILENAME    Javacore filename:    /opt/corp/payments/javacore.txt");
        VerifyReport report = verifier.verify(ORIGINAL, leaked);
        assertFalse(report.passed(), "1TIFILENAME with content is a leak (SPEC 5-B.9)");
        assertTrue(report.residualIdentifiers().stream()
                        .anyMatch(f -> f.kind() == Finding.Kind.FILENAME_CONTENT),
                report.residualIdentifiers().toString());
    }

    // --- §5-B.2 amendment: version re-emitted from the stripped CI section --
    // On a real javacore the only version line is 1CIJAVAVERSION; mask strips
    // the CI/ENVINFO section and re-emits the payload as 1XMJAVAVERSION (the
    // token the ThreadMine parser reads). The anchor bookkeeping must treat
    // that re-emission as intact — and its absence as broken.

    @Test
    void reemittedVersionAnchorIsIntactWhenOriginalOnlyHadTheCiForm() {
        String original = ORIGINAL
                .replace("1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)\n", "")
                .replace("0SECTION       ENVINFO subcomponent dump routine",
                        "0SECTION       ENVINFO subcomponent dump routine\n"
                                + "1CIJAVAVERSION JRE 17 Linux amd64-64 (build 17.0.9+9)");
        String masked = MASKED
                .replace("1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)\n", "")
                .replace("# [tm-anon: stripped section ENVINFO]",
                        "# [tm-anon: stripped section ENVINFO]\n"
                                + "1XMJAVAVERSION JRE 17 Linux amd64-64 (build 17.0.9+9)");
        VerifyReport report = verifier.verify(original, masked);
        assertEquals(java.util.List.of(), report.residualIdentifiers());
        assertTrue(report.brokenAnchors().isEmpty(), report.brokenAnchors().toString());
        assertTrue(report.passed());
    }

    @Test
    void missingReemittedVersionBreaksTheAnchorWhenOriginalHadTheCiForm() {
        String original = ORIGINAL
                .replace("1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)\n", "")
                .replace("0SECTION       ENVINFO subcomponent dump routine",
                        "0SECTION       ENVINFO subcomponent dump routine\n"
                                + "1CIJAVAVERSION JRE 17 Linux amd64-64 (build 17.0.9+9)");
        String masked = MASKED
                .replace("1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)\n", "");
        VerifyReport report = verifier.verify(original, masked);
        assertFalse(report.passed(), "a dropped version line must break the 1XMJAVAVERSION anchor");
        assertTrue(report.brokenAnchors().stream().anyMatch(a -> a.marker().equals("1XMJAVAVERSION")),
                report.brokenAnchors().toString());
    }

    @Test
    void rawJavacoreFailsWithFrameAndThreadFindings() {
        VerifyReport report = verifier.verify(ORIGINAL, ORIGINAL);
        assertFalse(report.passed());
        assertTrue(report.residualIdentifiers().stream()
                        .anyMatch(f -> f.value().contains("acme")),
                "the raw slash-form application frame must be reported: "
                        + report.residualIdentifiers());
        assertTrue(report.residualIdentifiers().stream()
                        .anyMatch(f -> f.kind() == Finding.Kind.THREAD_NAME
                                && f.value().startsWith("pgto-worker")),
                report.residualIdentifiers().toString());
    }

    @Test
    void allowlistSlashFramesAndNeutralQuotedMetadataAreNotFindings() {
        VerifyReport report = verifier.verify(ORIGINAL, MASKED);
        // java/lang and java/util slash frames, the "user" dump event and the
        // "Application" CPU category all survive masking on purpose.
        assertEquals(java.util.List.of(), report.residualIdentifiers());
    }

    // --- JIT moulding inside the source parenthesis (old javacores) ---------

    /** Same masked shape as MASKED, with the frames the JIT moulding rides on. */
    private static String maskedWithCompiledCode(String applicationSource) {
        return String.join("\n",
                "# tm-anon v1",
                "1TISIGINFO     signal 3 received",
                "2XMFULLTHDDUMP Full thread dump Classic VM (J2RE 1.4.2 IBM Windows 32, native threads):",
                "3XMTHREADINFO      \"t11111x22222\" (TID:0x2A29CF8, sys_thread_t:0x2412E78, state:R) prio=5",
                "4XESTACKTRACE          at java.lang.Object.wait(Object.java(Compiled Code))",
                "4XESTACKTRACE          at paaaaaxbbbbb.pcccccxddddd.C11111x22222.m33333x44444("
                        + applicationSource + ")",
                "");
    }

    /**
     * Old IBM javacores glue the JIT moulding to the source file inside the
     * frame parenthesis and omit the line number:
     * {@code (WalletService.java(Compiled Code))}. The rewriter tokenizes the
     * file name and keeps the moulding verbatim (SPEC §5.1) — the verifier has
     * to read it back the same way, or a correctly masked JDK 1.4-era javacore
     * is condemned on a frame that has nothing left to leak.
     */
    @Test
    void acceptsMaskedSourceFileWearingTheCompiledCodeMoulding() {
        String masked = maskedWithCompiledCode("C11111x22222.java(Compiled Code)");
        VerifyReport report = verifier.verify(masked, masked);
        assertEquals(java.util.List.of(), report.residualIdentifiers(),
                report.residualIdentifiers().toString());
        assertTrue(report.passed());
    }

    /** Some javacores drop the file name entirely and leave only the moulding. */
    @Test
    void acceptsTheBareCompiledCodeLocation() {
        String masked = maskedWithCompiledCode("Compiled Code");
        VerifyReport report = verifier.verify(masked, masked);
        assertEquals(java.util.List.of(), report.residualIdentifiers(),
                report.residualIdentifiers().toString());
    }

    /** Cutting the moulding must not blind the check to the file name under it. */
    @Test
    void stillReportsAnUnmaskedSourceFileWearingTheCompiledCodeMoulding() {
        String dump = maskedWithCompiledCode("LedgerService.java(Compiled Code)");
        VerifyReport report = verifier.verify(dump, dump);
        assertFalse(report.passed(), "an unmasked source file is a leak, moulding or not");
        assertTrue(report.residualIdentifiers().stream()
                        .anyMatch(f -> f.kind() == Finding.Kind.SOURCE_FILE
                                && f.value().contains("LedgerService")),
                report.residualIdentifiers().toString());
    }

    @Test
    void unknownCpuCategoryIsAFinding() {
        String leaked = MASKED.replace("current category=\"Application\"",
                "current category=\"corp-billing-engine\"");
        VerifyReport report = verifier.verify(ORIGINAL, leaked);
        assertFalse(report.passed(), "a non-JVM category string could carry a name");
    }
}

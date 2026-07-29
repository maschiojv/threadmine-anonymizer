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

    @Test
    void unknownCpuCategoryIsAFinding() {
        String leaked = MASKED.replace("current category=\"Application\"",
                "current category=\"corp-billing-engine\"");
        VerifyReport report = verifier.verify(ORIGINAL, leaked);
        assertFalse(report.passed(), "a non-JVM category string could carry a name");
    }
}

package dev.threadmine.anon.format.openj9;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.TokenType;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.hotspot.MaskResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SPEC §5-B, rule by rule, over minimal synthetic javacores. The corpus golden
 * tests exercise the full files; this class pins each contract clause in
 * isolation so a regression names the broken rule.
 */
class JavacoreRewriterTest {

    private static final String TITLE = String.join("\n",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       TITLE subcomponent dump routine",
            "NULL           ===============================",
            "1TISIGINFO     signal 3 received",
            "1TIDATETIME    Date:                 2026/02/10 at 09:30:11",
            "1TIFILENAME    Javacore filename:    D:\\corp\\payserver\\javacore.20260210.txt");

    private static final String CI = String.join("\n",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       CI subcomponent dump routine",
            "NULL           ============================",
            "1CICMDLINE     D:\\corp\\java\\bin\\java -Dcorp.db.password=Sw0rdf1sh! com.corp.PayServer",
            "1CISYSCP       Sys Classpath:   D:\\corp\\lib\\corp-pay-core-2.4.1.jar");

    private static final String XM_CLASSIC = String.join("\n",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       XM subcomponent dump routine",
            "NULL           ============================",
            "1XMTHDINFO     All Thread Details",
            "NULL           ------------------",
            "2XMFULLTHDDUMP Full thread dump Classic VM (J2RE 1.4.2 IBM Windows 32 build cn142sr2w, native threads):",
            "3XMTHREADINFO      \"corp-worker-1\" (TID:0x2A29CF8, sys_thread_t:0x2412E78, state:CW, native ID:0x107C) prio=5",
            "4XESTACKTRACE          at java.lang.Object.wait(Native Method)",
            "4XESTACKTRACE          at com.corp.kernel.QueueWorker.run(QueueWorker.java:172)",
            "3XMTHREADINFO      \"Signal dispatcher\" (TID:0x2A2B960, sys_thread_t:0x1A875E0, state:R, native ID:0x1580) prio=5");

    private static final String END = String.join("\n",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       Javadump End section",
            "NULL           ---------------------- END OF DUMP -------------------------------------",
            "");

    private static final String CLASSIC = String.join("\n", TITLE, CI, XM_CLASSIC, END);

    private static final String MODERN = String.join("\n",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       TITLE subcomponent dump routine",
            "NULL           ===============================",
            "1TICHARSET     UTF-8",
            "1TISIGINFO     Dump Event \"user\" (00004000) received",
            "1TIDATETIME    Date: 2026/02/10 at 09:30:11:224 (UTC)",
            "1TIFILENAME    Javacore filename:    /opt/corp/payments/javacore.20260210.txt",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       ENVINFO subcomponent dump routine",
            "NULL           =================================",
            "1CIJAVAVERSION JRE 17 Linux amd64-64 (build 17.0.9+9)",
            "2CIENVVAR      CORP_DB_PASSWORD=Hunter2!",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       THREADS subcomponent dump routine",
            "NULL           =================================",
            "NULL",
            "1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)",
            "1XMPOOLINFO    JVM Thread pool info:",
            "2XMPOOLTOTAL             Current total number of pooled threads: 3",
            "3XMTHREADINFO      \"pgto-worker-1\" J9VMThread:0x0000000000ABC100, omrthread_t:0x00007F30C4108908, java/lang/Thread:0x00000000FFE1D5A0, state:B, prio=5",
            "3XMJAVALTHREAD            (java/lang/Thread getId:0x21, isDaemon:true)",
            "3XMTHREADINFO1            (native thread ID:0x2B31, native priority:0x5, native policy:UNKNOWN, vmstate:B, vm thread flags:0x00000081)",
            "3XMCPUTIME               CPU usage total: 12.470131900 secs, current category=\"Application\"",
            "3XMTHREADBLOCK     Blocked on: com/corp/payment/WalletService@0x00000000E00A2C48 Owned by: \"pgto-worker-2\" (J9VMThread:0x0000000000ABD200, java/lang/Thread:0x00000000FFE1D6B0)",
            "3XMTHREADINFO3           Java.lang.Thread.State: BLOCKED",
            "4XESTACKTRACE                at com/corp/payment/WalletService.debit(WalletService.java:88(Compiled Code))",
            "4XESTACKTRACE                at java/lang/Thread.run(Thread.java:857)",
            "3XMTHREADINFO      \"pgto-worker-2\" J9VMThread:0x0000000000ABD200, omrthread_t:0x00007F30C4109A18, java/lang/Thread:0x00000000FFE1D6B0, state:R, prio=5",
            "3XMTHREADINFO3           Java.lang.Thread.State: RUNNABLE",
            "4XESTACKTRACE                at java/util/concurrent/LinkedBlockingQueue.take(LinkedBlockingQueue.java:435)",
            "3XMTHREADINFO      Anonymous native thread",
            "3XMTHREADINFO1            (native thread ID:0x2B44, native priority:0x0, native policy:UNKNOWN)",
            "4XENATIVESTACK               (0x00007F30C89123AB [libj9prt29.so+0x123ab])",
            "NULL           ------------------------------------------------------------------------",
            "0SECTION       Javadump End section",
            "NULL           ---------------------- END OF DUMP -------------------------------------",
            "");

    @TempDir
    Path tempDir;

    private TokenEngine engine;
    private JavacoreRewriter rewriter;

    @BeforeEach
    void setUp() {
        engine = new HmacTokenEngine(Vault.create(tempDir.resolve("vault.json")));
        rewriter = new JavacoreRewriter(engine, AllowlistMatcher.fromClasspath());
    }

    // --- §5-B.8: output marker -------------------------------------------

    @Test
    void firstOutputLineIsTheMarker() {
        String out = rewriter.mask(CLASSIC).output();
        assertEquals("# tm-anon v1", out.lines().findFirst().orElseThrow());
    }

    // --- §5-B.1: a detection token survives inside the first 4KB ----------

    @Test
    void detectionAnchorSurvivesInsideFirstFourKb() {
        String out = rewriter.mask(CLASSIC).output();
        String probe = out.length() > 4096 ? out.substring(0, 4096) : out;
        assertTrue(probe.contains("1TISIGINFO"), "1TISIGINFO must survive within 4KB");
    }

    // --- §5-B.2: forbidden sections stripped to a single marker line ------

    @Test
    void forbiddenSectionCollapsesIntoOneMarkerLine() {
        String out = rewriter.mask(CLASSIC).output();
        assertTrue(out.contains("# [tm-anon: stripped section CI]"), out);
        assertFalse(out.contains("1CICMDLINE"), "CI content must not survive");
        assertFalse(out.contains("Sw0rdf1sh"), "cmdline secrets must not survive");
        assertFalse(out.contains("1CISYSCP"), "classpath must not survive");
        assertEquals(1, out.lines().filter(l -> l.contains("stripped section CI")).count());
    }

    @Test
    void modernSectionNamesAreClassifiedByTokenFamilyNotSectionText() {
        String out = rewriter.mask(MODERN).output();
        // ENVINFO carries CI-family tokens: stripped even though the 0SECTION text differs
        assertTrue(out.contains("# [tm-anon: stripped section ENVINFO]"), out);
        assertFalse(out.contains("Hunter2"), "env secrets must not survive");
        // THREADS carries XM-family tokens: preserved even though it is not named "XM"
        assertTrue(out.contains("0SECTION       THREADS subcomponent dump routine"));
        assertTrue(out.contains("1XMJAVAVERSION JRE 17 Linux amd64-64 build 17.0.9+9 (openj9-0.41.0)"));
    }

    // --- §5-B.3: TITLE minimal, 1TIFILENAME always redacted ---------------

    @Test
    void titleKeepsSiginfoAndDatetimeButRedactsFilename() {
        String out = rewriter.mask(CLASSIC).output();
        assertTrue(out.contains("1TISIGINFO     signal 3 received"));
        assertTrue(out.contains("1TIDATETIME    Date:                 2026/02/10 at 09:30:11"));
        assertFalse(out.contains("javacore.20260210"), "local path must not survive");
        assertFalse(out.contains("D:\\corp"), "local path must not survive");
        assertTrue(out.lines().anyMatch(l -> l.startsWith("1TIFILENAME")
                        && l.substring("1TIFILENAME".length()).trim().equals("[tm-anon: redacted]")),
                "1TIFILENAME must keep its token and lose its content: " + out);
    }

    // --- §5-B.4: thread names by §5.3, native identity fields verbatim ----

    @Test
    void threadNameIsTokenizedWithSuffixAndNativeIdsStayVerbatim() {
        String out = rewriter.mask(CLASSIC).output();
        String base = engine.tokenize(TokenType.THREAD_NAME, "corp-worker");
        assertTrue(out.contains("\"" + base + "-1\" (TID:0x2A29CF8, sys_thread_t:0x2412E78, state:CW, native ID:0x107C) prio=5"),
                out);
        assertFalse(out.contains("corp-worker"), "original thread name must not survive");
    }

    @Test
    void allowlistedThreadNameStaysVerbatim() {
        String out = rewriter.mask(CLASSIC).output();
        assertTrue(out.contains("\"Signal dispatcher\" (TID:0x2A2B960"));
    }

    @Test
    void modernNativeIdentityFieldsStayVerbatim() {
        String out = rewriter.mask(MODERN).output();
        assertTrue(out.contains("J9VMThread:0x0000000000ABC100"));
        assertTrue(out.contains("omrthread_t:0x00007F30C4108908"));
        assertTrue(out.contains("java/lang/Thread:0x00000000FFE1D5A0"));
        assertFalse(out.contains("pgto-worker"), "original pool name must not survive");
    }

    // --- §5-B.4 + §5.1: frames -------------------------------------------

    @Test
    void allowlistFrameStaysVerbatimIncludingSlashForm() {
        String out = rewriter.mask(MODERN).output();
        assertTrue(out.contains("4XESTACKTRACE                at java/util/concurrent/LinkedBlockingQueue.take(LinkedBlockingQueue.java:435)"),
                "slash-form java.* frame must be recognized as allowlist and preserved: " + out);
        String classicOut = rewriter.mask(CLASSIC).output();
        assertTrue(classicOut.contains("4XESTACKTRACE          at java.lang.Object.wait(Native Method)"));
    }

    @Test
    void applicationFrameIsTokenizedWithDotSeparators() {
        String out = rewriter.mask(CLASSIC).output();
        String expected = "at "
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com") + "."
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.corp") + "."
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.corp.kernel") + "."
                + engine.tokenize(TokenType.CLASS_NAME, "com.corp.kernel.QueueWorker") + "."
                + engine.tokenize(TokenType.METHOD_NAME, "com.corp.kernel.QueueWorker#run")
                + "(" + engine.tokenize(TokenType.CLASS_NAME, "com.corp.kernel.QueueWorker") + ".java:172)";
        assertTrue(out.contains(expected), "expected tokenized frame: " + expected + "\nin: " + out);
        assertFalse(out.contains("QueueWorker"), "class name must not survive");
    }

    @Test
    void slashFrameIsTokenizedWithSlashSeparatorsAndSameCanonicalTokens() {
        String out = rewriter.mask(MODERN).output();
        String expected = "at "
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com") + "/"
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.corp") + "/"
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.corp.payment") + "/"
                + engine.tokenize(TokenType.CLASS_NAME, "com.corp.payment.WalletService") + "."
                + engine.tokenize(TokenType.METHOD_NAME, "com.corp.payment.WalletService#debit")
                + "(" + engine.tokenize(TokenType.CLASS_NAME, "com.corp.payment.WalletService")
                + ".java:88(Compiled Code))";
        assertTrue(out.contains(expected), "expected tokenized slash frame: " + expected + "\nin: " + out);
        assertFalse(out.contains("WalletService"), "class name must not survive");
        assertFalse(out.contains("com/corp"), "slash package must not survive");
    }

    // --- §5-B.5: Blocked on tokenized, address verbatim, owner consistent --

    @Test
    void blockedOnTargetIsTokenizedAddressVerbatimOwnerGetsTheHeaderToken() {
        String out = rewriter.mask(MODERN).output();
        String classToken = engine.tokenize(TokenType.PACKAGE_SEGMENT, "com") + "/"
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.corp") + "/"
                + engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.corp.payment") + "/"
                + engine.tokenize(TokenType.CLASS_NAME, "com.corp.payment.WalletService");
        String ownerToken = engine.tokenize(TokenType.THREAD_NAME, "pgto-worker") + "-2";
        assertTrue(out.contains("Blocked on: " + classToken + "@0x00000000E00A2C48 Owned by: \"" + ownerToken + "\""),
                out);
        // the owner reference must resolve to the same token used on that thread's own header
        assertTrue(out.contains("\"" + ownerToken + "\" J9VMThread:0x0000000000ABD200"), out);
    }

    // --- §5-B.6: fail-closed inside preserved sections and unknown sections -

    @Test
    void unknownSectionIsStrippedWhole() {
        String out = rewriter.mask(CLASSIC).output();
        assertTrue(out.contains("# [tm-anon: stripped section Javadump End section]"), out);
        assertFalse(out.contains("END OF DUMP"));
    }

    @Test
    void unrecognizedLineInsidePreservedSectionIsRedacted() {
        MaskResult result = rewriter.mask(MODERN);
        String out = result.output();
        assertFalse(out.contains("Anonymous native thread"), "quoteless header has no rule: redact");
        assertFalse(out.contains("4XENATIVESTACK"), "native stacks have no rule: redact");
        assertFalse(out.contains("libj9prt29"));
        assertTrue(out.contains("# [tm-anon: redacted]"));
        assertTrue(result.redactedLines() >= 2);
        assertFalse(result.warnings().isEmpty(), "each redaction must leave a warning");
    }

    @Test
    void neutralThreadMetadataLinesArePreserved() {
        String out = rewriter.mask(MODERN).output();
        assertTrue(out.contains("3XMJAVALTHREAD            (java/lang/Thread getId:0x21, isDaemon:true)"));
        assertTrue(out.contains("3XMTHREADINFO1            (native thread ID:0x2B31, native priority:0x5, native policy:UNKNOWN, vmstate:B, vm thread flags:0x00000081)"));
        assertTrue(out.contains("3XMCPUTIME               CPU usage total: 12.470131900 secs, current category=\"Application\""));
        assertTrue(out.contains("3XMTHREADINFO3           Java.lang.Thread.State: BLOCKED"));
    }

    // --- §5-B.7: relative order of THREADINFO/STACKTRACE preserved ---------

    @Test
    void threadInfoAndStackTraceOrderIsPreserved() {
        String out = rewriter.mask(MODERN).output();
        List<String> kinds = out.lines()
                .filter(l -> l.startsWith("3XMTHREADINFO      \"") || l.startsWith("4XESTACKTRACE"))
                .map(l -> l.startsWith("3XMTHREADINFO") ? "T" : "S")
                .toList();
        assertEquals(List.of("T", "S", "S", "T", "S"), kinds);
    }

    // --- structure: no blank lines invented, NULL separators preserved -----

    @Test
    void nullSeparatorLinesInsidePreservedSectionsSurvive() {
        String out = rewriter.mask(MODERN).output();
        assertTrue(out.lines().anyMatch(l -> l.equals("NULL")), "bare NULL separators must survive");
        assertEquals(0, out.lines().filter(String::isBlank).count() - blankCount(MODERN),
                "no blank line may be created or removed");
    }

    private static long blankCount(String text) {
        return text.lines().filter(String::isBlank).count();
    }
}

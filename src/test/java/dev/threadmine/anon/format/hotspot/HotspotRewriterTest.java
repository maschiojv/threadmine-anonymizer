package dev.threadmine.anon.format.hotspot;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.Vault;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One test per normative rewrite rule of SPEC §5. The fixture snippets are
 * minimal, synthetic lines; the full corpus is exercised by the golden tests.
 */
class HotspotRewriterTest {

    @TempDir
    Path tempDir;

    private TokenEngine engine;
    private HotspotRewriter rewriter;

    @BeforeEach
    void setUp() {
        Vault vault = Vault.create(tempDir.resolve("vault.json"));
        engine = new HmacTokenEngine(vault);
        rewriter = new HotspotRewriter(engine, AllowlistMatcher.fromClasspath());
    }

    private String mask(String text) {
        return rewriter.mask(text).output();
    }

    private List<String> maskLines(String text) {
        return mask(text).lines().toList();
    }

    // --- SPEC §5.9: output marker ----------------------------------------

    @Test
    void outputStartsWithVersionMarker() {
        List<String> lines = maskLines("\"main\" #1 prio=5 tid=0x1 nid=0x1 runnable\n");
        assertEquals("# tm-anon v1", lines.get(0));
    }

    // --- SPEC §5.1: frames ------------------------------------------------

    @Test
    void allowlistFrameStaysVerbatim() {
        String frame = "\tat java.lang.Thread.run(Thread.java:748)";
        assertTrue(mask(frame + "\n").contains(frame));
    }

    @Test
    void applicationFrameIsFullyTokenized() {
        String out = mask("\tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)\n");
        assertFalse(out.contains("acme"));
        assertFalse(out.contains("LedgerService"));
        assertFalse(out.contains("applyEntry"));
        assertTrue(out.contains(":88)"), "line number must survive: " + out);
        assertTrue(out.contains(".java:88)"), "file suffix .java must survive: " + out);
        Matcher m = Pattern.compile("\tat (p[0-9a-f]{5}x[0-9a-f]{5})\\.(p[0-9a-f]{5}x[0-9a-f]{5})\\."
                + "(p[0-9a-f]{5}x[0-9a-f]{5})\\.(C[0-9a-f]{5}x[0-9a-f]{5})\\.(m[0-9a-f]{5}x[0-9a-f]{5})"
                + "\\((C[0-9a-f]{5}x[0-9a-f]{5})\\.java:88\\)").matcher(out);
        assertTrue(m.find(), "frame must become p.p.p.C.m(C.java:88): " + out);
        // file token equals the class token (same canonical FQCN)
        assertEquals(m.group(4), m.group(6));
    }

    @Test
    void packageSegmentsUnderDifferentParentsGetDifferentTokens() {
        String out = mask("""
                \tat com.acme.billing.A.m(A.java:1)
                \tat com.other.billing.B.m(B.java:2)
                """);
        Matcher m = Pattern.compile("at p[0-9a-f]{5}x[0-9a-f]{5}\\.(p[0-9a-f]{5}x[0-9a-f]{5})\\.(p[0-9a-f]{5}x[0-9a-f]{5})").matcher(out);
        assertTrue(m.find());
        String firstBilling = m.group(2);
        assertTrue(m.find());
        String secondBilling = m.group(2);
        assertNotEquals(firstBilling, secondBilling,
                "same segment name under different parents must yield different tokens");
    }

    @Test
    void nativeMethodAndUnknownSourceArePreserved() {
        String out = mask("""
                \tat com.acme.a.A.x(Native Method)
                \tat com.acme.a.A.y(Unknown Source)
                """);
        assertTrue(out.contains("(Native Method)"));
        assertTrue(out.contains("(Unknown Source)"));
        assertFalse(out.contains("acme"));
    }

    @Test
    void modulePrefixInsideParenthesesIsPreserved() {
        String frame = "\tat java.lang.Thread.sleep0(java.base@21.0.3/Native Method)";
        assertTrue(mask(frame + "\n").contains(frame));
    }

    @Test
    void mxbeanClassloaderPrefixIsPreservedBeforeTokenizedFqcn() {
        String out = mask("\tat app//com.acme.gateway.Bootstrap.main(Bootstrap.java:41)\n");
        assertTrue(out.contains("at app//p"), "app// prefix must survive before the token: " + out);
        assertFalse(out.contains("acme"));
    }

    @Test
    void jcmdTextFrameWithoutAtKeywordIsTokenized() {
        String out = mask("      com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)\n");
        assertFalse(out.contains("acme"));
        assertTrue(out.contains(".java:88)"));
        assertTrue(out.startsWith("# tm-anon v1\n      p"), "6-space indent must survive: " + out);
    }

    @Test
    void jcmdTextModuleSlashPrefixStaysVerbatimForJdkFrames() {
        String frame = "      java.base/java.lang.Thread.sleep(Thread.java:509)";
        assertTrue(mask(frame + "\n").contains(frame));
    }

    // --- SPEC §5.2: inner/lambda/proxy classes -----------------------------

    @Test
    void innerClassPartsAreTokenizedSeparately() {
        String out = mask("""
                \tat com.acme.stock.StockSync$Watcher.poll(StockSync.java:112)
                \tat com.acme.stock.StockSync$Watcher$1.compare(StockSync.java:131)
                """);
        assertFalse(out.contains("StockSync"));
        assertFalse(out.contains("Watcher"));
        Matcher m = Pattern.compile("(C[0-9a-f]{5}x[0-9a-f]{5})\\$(C[0-9a-f]{5}x[0-9a-f]{5})\\$(C[0-9a-f]{5}x[0-9a-f]{5})\\.").matcher(out);
        assertTrue(m.find(), "Outer$Inner$1 must become C...$C...$C...: " + out);
    }

    @Test
    void lambdaMethodKeepsItsMoulding() {
        String out = mask("\tat com.acme.order.OrderService.lambda$processOrder$0(OrderService.java:67)\n");
        assertFalse(out.contains("processOrder"));
        assertTrue(Pattern.compile("\\.lambda\\$m[0-9a-f]{5}x[0-9a-f]{5}\\$0\\(").matcher(out).find(),
                "lambda$met$0 must become lambda$<m...>$0: " + out);
    }

    @Test
    void generatedLambdaClassKeepsItsMoulding() {
        String out = mask("\tat com.acme.order.OrderService$$Lambda$123/0x00007f8a1c2b3c40.run(Unknown Source)\n");
        assertFalse(out.contains("OrderService"));
        assertTrue(out.contains("$$Lambda$123/0x00007f8a1c2b3c40"),
                "generated-class moulding must survive verbatim: " + out);
        assertTrue(out.contains("(Unknown Source)"));
    }

    @Test
    void jdk21StyleLambdaWithoutCounterKeepsItsMoulding() {
        String out = mask("\tat com.acme.stock.StockBootstrap$$Lambda/0x00003800011ad400.run(Unknown Source)\n");
        assertFalse(out.contains("StockBootstrap"));
        assertTrue(out.contains("$$Lambda/0x00003800011ad400"));
    }

    @Test
    void cglibProxiesKeepTheirMoulding() {
        String out = mask("""
                \tat com.acme.web.OrderController$$FastClassBySpringCGLIB$$1a2b3c4d.invoke(<generated>)
                \tat com.acme.web.OrderController$$EnhancerBySpringCGLIB$$aa11bb22.confirm(<generated>)
                """);
        assertFalse(out.contains("OrderController"));
        assertTrue(out.contains("$$FastClassBySpringCGLIB$$1a2b3c4d"));
        assertTrue(out.contains("$$EnhancerBySpringCGLIB$$aa11bb22"));
        assertTrue(out.contains("(<generated>)"));
    }

    @Test
    void constructorAndStaticInitializerNamesStayVerbatim() {
        String out = mask("""
                \tat com.acme.stock.StockCatalog.<clinit>(StockCatalog.java:19)
                \tat com.acme.stock.StockSync.<init>(StockSync.java:44)
                """);
        assertTrue(out.contains(".<clinit>("));
        assertTrue(out.contains(".<init>("));
        assertFalse(out.contains("Stock"));
    }

    // --- SPEC §5.3: thread names -------------------------------------------

    @Test
    void allowlistThreadNameStaysVerbatim() {
        String header = "\"http-nio-8080-exec-1\" #27 daemon prio=5 tid=0x1 nid=0x1 runnable";
        assertTrue(mask(header + "\n").contains(header));
    }

    @Test
    void routeLikeThreadNameBecomesSingleTokenWithRouteMarker() {
        String out = mask("\"sync-/api/orders?id=99887766\" #33 prio=5 tid=0x1 nid=0x1 runnable\n");
        assertFalse(out.contains("api"));
        assertFalse(out.contains("orders"));
        assertFalse(out.contains("99887766"));
        assertTrue(Pattern.compile("\"t[0-9a-f]{5}x[0-9a-f]{5}/q\" #33 prio=5").matcher(out).find(),
                "route-like name must become a single t.../q token: " + out);
    }

    @Test
    void uuidThreadNameTriggersRouteHeuristicBeforeSuffixRule() {
        String out = mask("\"worker-550e8400-e29b-41d4-a716-446655440000\" #34 prio=5 tid=0x1 nid=0x1 runnable\n");
        assertFalse(out.contains("550e8400"));
        assertFalse(out.contains("440000"), "suffix rule must not slice the UUID: " + out);
        assertTrue(Pattern.compile("\"t[0-9a-f]{5}x[0-9a-f]{5}/q\"").matcher(out).find());
    }

    @Test
    void numericSuffixIsPreservedNextToPrefixToken() {
        String out = mask("""
                "pgto-worker-1" #24 prio=5 tid=0x1 nid=0x1 runnable
                "pgto-worker-2" #25 prio=5 tid=0x2 nid=0x2 runnable
                "tenant-sync#4" #36 prio=5 tid=0x3 nid=0x3 runnable
                """);
        assertFalse(out.contains("pgto"));
        assertFalse(out.contains("tenant"));
        Matcher m = Pattern.compile("\"(t[0-9a-f]{5}x[0-9a-f]{5})-1\"").matcher(out);
        assertTrue(m.find(), "pgto-worker-1 must become <token>-1: " + out);
        String base = m.group(1);
        assertTrue(out.contains("\"" + base + "-2\""),
                "same pool prefix must share the same base token");
        assertTrue(Pattern.compile("\"t[0-9a-f]{5}x[0-9a-f]{5}#4\"").matcher(out).find(),
                "# also counts as a suffix separator: " + out);
    }

    @Test
    void wholeNameTokenizedWhenNoSuffixAndNoRoute() {
        String out = mask("\"order-dispatcher\" #29 prio=5 tid=0x1 nid=0x1 waiting on condition\n");
        assertFalse(out.contains("order-dispatcher"));
        assertTrue(Pattern.compile("\"t[0-9a-f]{5}x[0-9a-f]{5}\" #29").matcher(out).find());
    }

    @Test
    void emptyVirtualThreadNameKeepsItsQuotes() {
        String header = "\"\" #21 virtual prio=5 tid=0x1 nid=0x0 runnable";
        assertTrue(mask(header + "\n").contains(header));
    }

    @Test
    void jcmdTextHeaderTokenizesOnlyTheName() {
        String out = mask("#30 \"pgto-worker-1\" BLOCKED\n");
        assertFalse(out.contains("pgto"));
        assertTrue(Pattern.compile("#30 \"t[0-9a-f]{5}x[0-9a-f]{5}-1\" BLOCKED").matcher(out).find(), out);
    }

    /**
     * JDK 21..23 {@code Thread.dump_to_file -format=text}: the header carries
     * no state at all and the virtual marker is lowercase
     * ({@code jdk.internal.vm.ThreadDumper#dumpThread}, jdk-21+35:
     * {@code ps.format("#%d \"%s\"%s%n", threadId, name, isVirtual ? " virtual" : "")}).
     */
    @Test
    void jcmdTextHeaderWithoutStateIsRecognized() {
        MaskResult result = rewriter.mask("#1 \"main\"\n#22 \"\" virtual\n#30 \"pgto-worker-1\"\n");
        String out = result.output();

        assertEquals(0, result.redactedLines(), "stateless jcmd headers must be classified: " + result.warnings());
        assertTrue(out.contains("#22 \"\" virtual"), "anonymous virtual thread header must survive: " + out);
        assertFalse(out.contains("pgto"));
        assertTrue(Pattern.compile("#30 \"t[0-9a-f]{5}x[0-9a-f]{5}-1\"$", Pattern.MULTILINE).matcher(out).find(), out);
    }

    /** JDK 24+ text dump: {@code #N "name" virtual STATE <Instant>}. */
    @Test
    void jcmdTextHeaderWithLowercaseVirtualStateAndTimestampIsRecognized() {
        MaskResult result = rewriter.mask("#52 \"order-vt-9\" virtual WAITING 2026-07-24T13:44:02.114003Z\n");
        String out = result.output();

        assertEquals(0, result.redactedLines(), result.warnings().toString());
        assertTrue(out.contains(" virtual WAITING 2026-07-24T13:44:02.114003Z"),
                "state and timestamp must survive verbatim: " + out);
        assertFalse(out.contains("order-vt"));
    }

    @Test
    void jcmdTextHeaderWithUnknownTrailerFailsClosed() {
        MaskResult result = rewriter.mask("#7 \"main\" BLOCKED password=hunter2\n");

        assertEquals(1, result.redactedLines());
        assertFalse(result.output().contains("hunter2"));
    }

    @Test
    void mxbeanOwnedByReceivesTheSameTokenAsTheOwnedThreadHeader() {
        String out = mask("""
                "pgto-worker-1" Id=31 BLOCKED on com.acme.payment.LedgerLock@1f2e3d owned by "pgto-worker-2" Id=32
                "pgto-worker-2" Id=32 RUNNABLE (in native)
                """);
        assertFalse(out.contains("pgto"));
        assertFalse(out.contains("LedgerLock"));
        assertTrue(out.contains("@1f2e3d"), "lock identity hash must survive: " + out);
        Matcher header2 = Pattern.compile("\"(t[0-9a-f]{5}x[0-9a-f]{5})-2\" Id=32 RUNNABLE").matcher(out);
        assertTrue(header2.find(), out);
        assertTrue(out.contains("owned by \"" + header2.group(1) + "-2\" Id=32"),
                "owned-by reference must reuse the exact header token: " + out);
    }

    // --- SPEC §5.4: locks ---------------------------------------------------

    @Test
    void lockAddressesAreAlwaysVerbatimAndLockClassIsTokenized() {
        String out = mask("""
                \t- waiting to lock <0x00000000e1a2b3c8> (a com.acme.payment.LedgerLock)
                \t- locked <0x00000000e1a2b3c8> (a com.acme.payment.LedgerLock)
                \t- parking to wait for  <0x000000061f8d2a40> (a java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject)
                """);
        assertTrue(out.contains("<0x00000000e1a2b3c8>"));
        assertTrue(out.contains("- parking to wait for  <0x000000061f8d2a40> (a java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject)"),
                "allowlist lock class and double space must survive verbatim: " + out);
        assertFalse(out.contains("LedgerLock"));
        assertTrue(Pattern.compile("- waiting to lock <0x00000000e1a2b3c8> \\(a p[0-9a-f]{5}x[0-9a-f]{5}\\.p[0-9a-f]{5}x[0-9a-f]{5}\\.p[0-9a-f]{5}x[0-9a-f]{5}\\.C[0-9a-f]{5}x[0-9a-f]{5}\\)").matcher(out).find(), out);
    }

    @Test
    void reLockInWaitLineKeepsItsMouldingVerbatim() {
        String out = mask("\t- waiting to re-lock in wait() <0x000000070fe91238> (a com.acme.order.queue.OrderQueue)\n");
        assertTrue(out.contains("- waiting to re-lock in wait() <0x000000070fe91238> (a p"), out);
        assertFalse(out.contains("OrderQueue"));
    }

    @Test
    void noObjectReferenceSentinelIsVerbatim() {
        String line = "\t- waiting on <no object reference available>";
        assertTrue(mask(line + "\n").contains(line));
    }

    /**
     * The JDK 24+ jcmd text dump does not print monitor addresses: it prints
     * {@code Objects.toIdentityString(obj)}, i.e. {@code FQCN@hash}, inside the
     * angle brackets ({@code ThreadDumper#decorateObject}). Keeping the angle
     * content verbatim — which is right for an address — would ship the
     * application class name untouched.
     */
    @Test
    void monitorIdentityStringInsideAngleBracketsIsTokenized() {
        String out = mask("    - waiting to lock <com.acme.payment.LedgerLock@6e8cf4c6>\n"
                + "    - locked <java.util.concurrent.ThreadPoolExecutor$Worker@1a2b3c4d>\n");

        assertFalse(out.contains("acme"));
        assertFalse(out.contains("LedgerLock"));
        assertTrue(out.contains("@6e8cf4c6>"), "identity hash must survive verbatim: " + out);
        assertTrue(out.contains("    - locked <java.util.concurrent.ThreadPoolExecutor$Worker@1a2b3c4d>"),
                "allowlisted monitor class stays verbatim: " + out);
        assertTrue(Pattern.compile("- waiting to lock <p[0-9a-f]{5}x[0-9a-f]{5}\\.p[0-9a-f]{5}x[0-9a-f]{5}"
                + "\\.p[0-9a-f]{5}x[0-9a-f]{5}\\.C[0-9a-f]{5}x[0-9a-f]{5}@6e8cf4c6>").matcher(out).find(), out);
    }

    @Test
    void parkBlockerOwnerTrailerSurvives() {
        String out = mask("    - parking to wait for "
                + "<java.util.concurrent.locks.ReentrantLock$NonfairSync@5e8f9a3b>, owner #30\n");

        assertTrue(out.contains("<java.util.concurrent.locks.ReentrantLock$NonfairSync@5e8f9a3b>, owner #30"), out);
    }

    @Test
    void eliminatedLockLineIsPreserved() {
        String line = "    - lock is eliminated";
        assertTrue(mask(line + "\n").contains(line));
    }

    @Test
    void unknownAngleBracketContentFailsClosed() {
        MaskResult result = rewriter.mask("\t- locked <session password=hunter2>\n");

        assertEquals(1, result.redactedLines());
        assertFalse(result.output().contains("hunter2"));
    }

    @Test
    void unknownLockTrailerFailsClosed() {
        MaskResult result = rewriter.mask("\t- locked <0x00000000e1a2b3c8> owned by tenant acme-prod\n");

        assertEquals(1, result.redactedLines());
        assertFalse(result.output().contains("acme-prod"));
    }

    @Test
    void mxbeanLockLinesTokenizeClassAndKeepHash() {
        String out = mask("""
                \t-  blocked on com.acme.payment.LedgerLock@1f2e3d
                \t-  locked com.acme.payment.LedgerLock@1f2e3d
                \t- java.util.concurrent.locks.ReentrantLock$NonfairSync@5e8f9a
                """);
        assertFalse(out.contains("LedgerLock"));
        assertTrue(out.contains("@1f2e3d"));
        assertTrue(out.contains("- java.util.concurrent.locks.ReentrantLock$NonfairSync@5e8f9a"),
                "allowlist synchronizer entry stays verbatim: " + out);
        assertTrue(Pattern.compile("-  blocked on p[0-9a-f]{5}x[0-9a-f]{5}\\.p[0-9a-f]{5}x[0-9a-f]{5}\\.p[0-9a-f]{5}x[0-9a-f]{5}\\.C[0-9a-f]{5}x[0-9a-f]{5}@1f2e3d").matcher(out).find(), out);
    }

    // --- SPEC §5.5: deadlock block ------------------------------------------

    @Test
    void deadlockBlockReusesHeaderTokensAndKeepsStructure() {
        String out = mask("""
                "pgto-worker-1" #14 prio=5 tid=0x1 nid=0x1 waiting for monitor entry
                   java.lang.Thread.State: BLOCKED (on object monitor)

                Found one Java-level deadlock:
                =============================
                "pgto-worker-1":
                  waiting to lock monitor 0x00007fa86800fe00 (object 0x000000061fcc9b90, a com.acme.stock.StockLatch),
                  which is held by "pgto-worker-2"

                Java stack information for the threads listed above:
                ===================================================
                "pgto-worker-1":

                Found 1 deadlock.
                """);
        assertTrue(out.contains("Found one Java-level deadlock:"));
        assertTrue(out.contains("============================="));
        assertTrue(out.contains("Java stack information for the threads listed above:"));
        assertTrue(out.contains("Found 1 deadlock."));
        assertTrue(out.contains("monitor 0x00007fa86800fe00 (object 0x000000061fcc9b90, a "));
        assertFalse(out.contains("pgto"));
        assertFalse(out.contains("StockLatch"));
        // header token == deadlock block token
        Matcher header = Pattern.compile("\"(t[0-9a-f]{5}x[0-9a-f]{5})-1\" #14").matcher(out);
        assertTrue(header.find(), out);
        assertTrue(out.contains("\"" + header.group(1) + "-1\":"),
                "deadlock name line must reuse the header token: " + out);
        assertTrue(Pattern.compile("which is held by \"t[0-9a-f]{5}x[0-9a-f]{5}-2\"").matcher(out).find(), out);
    }

    // --- SPEC §5.6: untouchable structure -----------------------------------

    @Test
    void structuralLinesAreByteForByteVerbatim() {
        String text = """
                2026-07-24 09:44:02
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode, sharing):

                   java.lang.Thread.State: TIMED_WAITING (sleeping)
                      <pinned: synchronized>
                      <virtual thread is mounted on carrier thread "ForkJoinPool-1-worker-1">
                """;
        String out = mask(text);
        for (String line : text.lines().toList()) {
            assertTrue(out.contains(line), "structural line must survive: [" + line + "]");
        }
    }

    @Test
    void carrierNameInsideLoomMarkerFollowsThreadNameRules() {
        String out = mask("      <virtual thread is mounted on carrier thread \"acme-carrier-1\">\n");
        assertFalse(out.contains("acme"));
        assertTrue(Pattern.compile("<virtual thread is mounted on carrier thread \"t[0-9a-f]{5}x[0-9a-f]{5}-1\">").matcher(out).find(), out);
    }

    /**
     * A mounted carrier prints {@code Carrying virtual thread #N} INSTEAD of
     * its {@code java.lang.Thread.State:} line. The number is a thread id, not
     * a name, and the ThreadMine parser reads the line
     * ({@code ParserHotSpotCore.CARRYING_VIRTUAL}) — so it stays byte for byte.
     */
    @Test
    void carryingVirtualThreadLineIsVerbatim() {
        String line = "   Carrying virtual thread #32";
        assertTrue(mask(line + "\n").contains(line));
    }

    @Test
    void carrierBlockWithoutStateLineIsFullyClassified() {
        MaskResult result = rewriter.mask("""
                "ForkJoinPool-1-worker-1" #33 [33539] daemon prio=5 os_prio=31 cpu=33651.61ms elapsed=33.65s tid=0x000000013289f000
                   Carrying virtual thread #32
                \tat java.lang.VirtualThread.runContinuation(java.base@25/VirtualThread.java:297)
                \tat com.acme.order.OrderService.processOrder(OrderService.java:67)
                """);

        assertEquals(0, result.redactedLines(), result.warnings().toString());
        assertTrue(result.output().contains("   Carrying virtual thread #32"));
        assertFalse(result.output().contains("acme"));
    }

    @Test
    void blankLinesAreNeverCreatedNorRemoved() {
        String text = """
                "a-worker-1" #1 prio=5 tid=0x1 nid=0x1 runnable
                   java.lang.Thread.State: RUNNABLE

                "b-worker-1" #2 prio=5 tid=0x2 nid=0x2 runnable
                   java.lang.Thread.State: RUNNABLE
                """;
        long blanksIn = text.lines().filter(String::isBlank).count();
        long blanksOut = mask(text).lines().filter(String::isBlank).count();
        assertEquals(blanksIn, blanksOut);
    }

    // --- SPEC §5.7: strip ---------------------------------------------------

    @Test
    void smrBlockIsStrippedWithMarker() {
        String out = mask("""
                Threads class SMR info:
                _java_thread_list=0x00006000021e6f50, length=6, elements={
                0x00007fa894019000, 0x00007fa895008800,
                0x00007fa89483c000
                }

                "main" #1 prio=5 tid=0x1 nid=0x1 runnable
                """);
        assertFalse(out.contains("SMR"));
        assertFalse(out.contains("_java_thread_list"));
        assertTrue(out.contains("# [tm-anon: stripped]"));
        assertEquals(1, out.lines().filter(l -> l.equals("# [tm-anon: stripped]")).count(),
                "a contiguous stripped run collapses into one marker line");
        assertEquals(1, out.lines().filter(String::isBlank).count(), "blank line count preserved");
    }

    @Test
    void jniRefsAndCompilerLinesAreStripped() {
        String out = mask("""
                   Compiling: 8402   4       com.acme.report.PdfRenderer::renderPage (312 bytes)
                   No compile task
                JNI global references: 245
                JNI global refs: 19, weak refs: 0
                """);
        assertFalse(out.contains("Compiling"));
        assertFalse(out.contains("PdfRenderer"));
        assertFalse(out.contains("No compile task"));
        assertFalse(out.contains("JNI"));
    }

    @Test
    void lockedOwnableSynchronizersBlockIsStripped() {
        String out = mask("""
                   Locked ownable synchronizers:
                \t- <0x000000061f8a2b40> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)

                "next-thread-1" #2 prio=5 tid=0x2 nid=0x2 runnable
                """);
        assertFalse(out.contains("synchronizers"));
        assertFalse(out.contains("0x000000061f8a2b40"));
        assertEquals(1, out.lines().filter(String::isBlank).count(),
                "the blank line delimiting the next thread must survive");
    }

    @Test
    void heapSectionIsStripped() {
        String out = mask("""
                Heap
                 PSYoungGen      total 76288K, used 65313K [0x00000000f5580000, 0x00000000fab00000, 0x0000000100000000)
                  eden space 65536K, 91% used [0x00000000f5580000,0x00000000f91a8560,0x00000000f9580000)
                """);
        assertFalse(out.contains("PSYoungGen"));
        assertFalse(out.contains("eden"));
    }

    // --- SPEC §5.8: fail-closed --------------------------------------------

    @Test
    void unclassifiedLineIsRedactedWithWarning() {
        MaskResult result = rewriter.mask("some totally unexpected line with secrets: password=hunter2\n");
        assertFalse(result.output().contains("hunter2"));
        assertTrue(result.output().contains("# [tm-anon: redacted]"));
        assertEquals(1, result.redactedLines());
        assertFalse(result.warnings().isEmpty(), "redaction must produce a warning");
    }

    @Test
    void jcmdPreambleLinesAreNotRedacted() {
        String out = mask("""
                48350:
                48350
                2026-07-24T13:02:19.482190Z
                21.0.3+9-LTS
                """);
        assertTrue(out.contains("48350:"));
        assertTrue(out.contains("2026-07-24T13:02:19.482190Z"));
        assertTrue(out.contains("21.0.3+9-LTS"));
        assertFalse(out.contains("redacted"));
    }

    // --- counters -----------------------------------------------------------

    @Test
    void summaryCountersAddUp() {
        MaskResult result = rewriter.mask("""
                "pgto-worker-1" #24 prio=5 tid=0x1 nid=0x1 runnable
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)
                JNI global refs: 19, weak refs: 0
                ??? garbage ???
                """);
        assertEquals(2, result.tokenizedLines());
        assertEquals(1, result.strippedLines());
        assertEquals(1, result.redactedLines());
        assertTrue(result.preservedLines() >= 1, "state line and trailing blank are preserved");
    }
}

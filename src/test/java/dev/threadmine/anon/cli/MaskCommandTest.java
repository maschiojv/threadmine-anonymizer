package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.Vault;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MaskCommandTest {

    private static final String DUMP = """
            Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode, sharing):

            "pgto-worker-1" #24 prio=5 os_prio=0 tid=0x1 nid=0x1 runnable
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:88)
            \tat java.lang.Thread.run(Thread.java:748)

            JNI global refs: 19, weak refs: 0
            """;

    @TempDir
    Path tempDir;

    private Path dumpFile;
    private Path vaultFile;
    private ByteArrayOutputStream stdout;
    private ByteArrayOutputStream stderr;

    @BeforeEach
    void setUp() throws IOException {
        dumpFile = tempDir.resolve("dump.txt");
        Files.writeString(dumpFile, DUMP);
        vaultFile = tempDir.resolve("vault.json");
        Vault.create(vaultFile);
        stdout = new ByteArrayOutputStream();
        stderr = new ByteArrayOutputStream();
    }

    private int run(String... args) {
        return Main.run(args,
                new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8));
    }

    private String out() {
        return stdout.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return stderr.toString(StandardCharsets.UTF_8);
    }

    @Test
    void masksToDefaultOutputPathAndPrintsSummary() throws IOException {
        int exit = run("mask", dumpFile.toString(), "--vault", vaultFile.toString());

        assertEquals(0, exit, err());
        Path defaultOut = tempDir.resolve("dump.anon.txt");
        assertTrue(Files.exists(defaultOut), "default output <dump>.anon.<ext> must be written");
        String masked = Files.readString(defaultOut);
        assertTrue(masked.startsWith("# tm-anon v1\n"));
        assertFalse(masked.contains("acme"));
        assertTrue(out().contains("preserved"), out());
        assertTrue(out().contains("tokenized"), out());
        assertTrue(out().contains("stripped"), out());
        assertTrue(out().contains("redacted"), out());
        assertTrue(out().toLowerCase().contains("neutral"),
                "summary must warn about uploading with a neutral file name/title: " + out());
    }

    @Test
    void explicitOutputPathIsHonored() throws IOException {
        Path outFile = tempDir.resolve("masked.txt");
        int exit = run("mask", dumpFile.toString(), "-o", outFile.toString(),
                "--vault", vaultFile.toString());

        assertEquals(0, exit, err());
        assertTrue(Files.exists(outFile));
        assertFalse(Files.exists(tempDir.resolve("dump.anon.txt")));
    }

    @Test
    void dryRunWritesNothing() {
        int exit = run("mask", dumpFile.toString(), "--dry-run", "--vault", vaultFile.toString());

        assertEquals(0, exit, err());
        assertFalse(Files.exists(tempDir.resolve("dump.anon.txt")), "dry-run must not write output");
        assertTrue(out().contains("dry-run"), out());
    }

    @Test
    void unsupportedFormatIsRefusedWithExitCode2() throws IOException {
        Path notADump = tempDir.resolve("notes.txt");
        Files.writeString(notADump, "just some meeting notes\nnothing thread-dump-like here\n");

        int exit = run("mask", notADump.toString(), "--vault", vaultFile.toString());

        assertEquals(2, exit);
        assertFalse(Files.exists(tempDir.resolve("notes.anon.txt")), "refused input must produce no output");
        assertTrue(err().toLowerCase().contains("format"), err());
    }

    @Test
    void missingVaultIsExitCode3WithInitHint() {
        int exit = run("mask", dumpFile.toString(), "--vault", tempDir.resolve("absent.json").toString());

        assertEquals(3, exit);
        assertTrue(err().contains("init"), "error must hint at tm-anon init: " + err());
    }

    @Test
    void missingInputFileIsAUsageError() {
        int exit = run("mask", tempDir.resolve("nope.txt").toString(), "--vault", vaultFile.toString());

        assertEquals(1, exit);
    }

    @Test
    void reportFileListsCountsAndWarnings() throws IOException {
        Files.writeString(dumpFile, DUMP + "??? unclassifiable garbage ???\n");
        Path report = tempDir.resolve("report.txt");

        int exit = run("mask", dumpFile.toString(), "--vault", vaultFile.toString(),
                "--report", report.toString());

        assertEquals(0, exit, err());
        String reportText = Files.readString(report);
        assertTrue(reportText.contains("redacted"), reportText);
        assertTrue(reportText.contains("fail-closed"), "warnings must be listed: " + reportText);
    }

    @Test
    void strictFlagTokenizesRecommendedTierPackages() throws IOException {
        Files.writeString(dumpFile, """
                "w-1" #1 prio=5 tid=0x1 nid=0x1 runnable
                   java.lang.Thread.State: RUNNABLE
                \tat com.google.common.cache.LocalCache.get(LocalCache.java:100)
                """);

        int exitDefault = run("mask", dumpFile.toString(), "--vault", vaultFile.toString(),
                "-o", tempDir.resolve("default.txt").toString());
        int exitStrict = run("mask", dumpFile.toString(), "--vault", vaultFile.toString(),
                "--strict", "-o", tempDir.resolve("strict.txt").toString());

        assertEquals(0, exitDefault, err());
        assertEquals(0, exitStrict, err());
        assertTrue(Files.readString(tempDir.resolve("default.txt")).contains("com.google.common.cache.LocalCache"),
                "recommended tier preserved by default");
        assertFalse(Files.readString(tempDir.resolve("strict.txt")).contains("LocalCache"),
                "--strict must tokenize recommended-tier packages");
    }

    @Test
    void javacoreIsRoutedToTheOpenJ9Rewriter() throws IOException {
        Path javacore = tempDir.resolve("javacore.20260210.093011.1.0001.txt");
        Files.writeString(javacore, """
                0SECTION       TITLE subcomponent dump routine
                1TISIGINFO     signal 3 received
                1TIDATETIME    Date: 2026/02/10 at 09:30:11
                1TIFILENAME    Javacore filename:    /opt/corp/javacore.txt
                0SECTION       CI subcomponent dump routine
                1CICMDLINE     /opt/java/bin/java -Dcorp.db.password=Hunter2! -jar corp.jar
                0SECTION       XM subcomponent dump routine
                3XMTHREADINFO      "corp-worker-1" (TID:0x2A29CF8, sys_thread_t:0x2412E78, state:R, native ID:0x107C) prio=5
                4XESTACKTRACE          at com.corp.kernel.QueueWorker.run(QueueWorker.java:172)
                """);
        Path outFile = tempDir.resolve("javacore.anon.txt");

        int exit = run("mask", javacore.toString(), "-o", outFile.toString(),
                "--vault", vaultFile.toString());

        assertEquals(0, exit, err());
        String masked = Files.readString(outFile);
        assertTrue(masked.startsWith("# tm-anon v1\n"));
        assertTrue(masked.contains("# [tm-anon: stripped section CI]"),
                "javacore must go through the section-strip rewriter: " + masked);
        assertFalse(masked.contains("Hunter2"), "CI secrets must not survive");
        assertFalse(masked.contains("corp-worker"), "thread names must be tokenized");
        assertTrue(masked.contains("1TISIGINFO     signal 3 received"));
    }

    @Test
    void refusalMessageNamesTheJavacoreDialect() throws IOException {
        Path notADump = tempDir.resolve("notes2.txt");
        Files.writeString(notADump, "just some meeting notes\nnothing thread-dump-like here\n");

        run("mask", notADump.toString(), "--vault", vaultFile.toString());

        assertTrue(err().contains("OpenJ9 javacore"),
                "the refusal must list javacore among supported formats: " + err());
    }

    @Test
    void sameVaultProducesSameTokensAcrossRuns() throws IOException {
        Path out1 = tempDir.resolve("a.txt");
        Path out2 = tempDir.resolve("b.txt");
        assertEquals(0, run("mask", dumpFile.toString(), "--vault", vaultFile.toString(), "-o", out1.toString()));
        assertEquals(0, run("mask", dumpFile.toString(), "--vault", vaultFile.toString(), "-o", out2.toString()));
        assertEquals(Files.readString(out1), Files.readString(out2));
    }
}

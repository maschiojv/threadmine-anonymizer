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
    void sameVaultProducesSameTokensAcrossRuns() throws IOException {
        Path out1 = tempDir.resolve("a.txt");
        Path out2 = tempDir.resolve("b.txt");
        assertEquals(0, run("mask", dumpFile.toString(), "--vault", vaultFile.toString(), "-o", out1.toString()));
        assertEquals(0, run("mask", dumpFile.toString(), "--vault", vaultFile.toString(), "-o", out2.toString()));
        assertEquals(Files.readString(out1), Files.readString(out2));
    }
}

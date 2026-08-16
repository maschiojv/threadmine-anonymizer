package dev.threadmine.anon.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(String... args) {
        return Main.run(args,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private int runIn(Path dir, String... args) {
        return Main.run(args, dir,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    @Test
    void noArgumentsPrintsUsageAndReturnsUsageExitCode() {
        int exit = run();

        String usage = err.toString(StandardCharsets.UTF_8);
        assertEquals(1, exit);
        assertTrue(usage.contains("tm-anon"), "usage must mention the tool name");
        assertTrue(usage.contains("init"), "usage must list the init command");
        assertTrue(usage.contains("mask"), "usage must list the mask command");
        assertTrue(usage.contains("unmask"), "usage must list the unmask command");
        assertTrue(usage.contains("verify"), "usage must list the verify command");
    }

    // The banner is a copy-paste surface: whatever it prints has to run as-is.
    // Under the test runner the launcher is not our jar, so the resolver lands
    // on the documented default - the same line a downloaded jar produces.
    @Test
    void usageSpellsTheCommandsTheWayTheyCanBeRun() {
        run();

        String usage = err.toString(StandardCharsets.UTF_8);
        assertTrue(usage.contains(Invocation.current() + " init"), usage);
        assertTrue(usage.contains(Invocation.current() + " unmask"), usage);
        assertTrue(usage.contains("java -jar tm-anon.jar init"),
                "a jar launch must not advertise a tm-anon command that does not exist");
        assertTrue(usage.contains("PATH"), "the banner must say how to get the short form");
    }

    @Test
    void usageDocumentsTheExitCodeContract() {
        run();

        String usage = err.toString(StandardCharsets.UTF_8);
        assertTrue(usage.contains("Exit codes"), usage);
        assertTrue(usage.contains("4"), "exit code 4 (verify failed) must be documented");
    }

    @Test
    void unknownCommandPrintsUsageAndReturnsUsageExitCode() {
        int exit = run("frobnicate");

        assertEquals(1, exit);
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("frobnicate"),
                "error must echo the unknown command");
    }

    // --- dispatch: each command reaches its implementation and its exit code

    @Test
    void initIsDispatchedAndSucceeds(@TempDir Path dir) {
        assertEquals(0, runIn(dir, "init"), err.toString(StandardCharsets.UTF_8));
        assertTrue(Files.exists(dir.resolve("tm-anon-vault.json")));
    }

    @Test
    void unmaskIsDispatchedAndReportsAMissingVaultAsAVaultError(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("report.json"), "t1a2b3xc4d5e");

        assertEquals(3, runIn(dir, "unmask", "report.json"));
    }

    @Test
    void unmaskIsDispatchedAndSucceedsEndToEnd(@TempDir Path dir) throws IOException {
        runIn(dir, "init");
        Files.writeString(dir.resolve("report.json"), "no tokens here");

        assertEquals(0, runIn(dir, "unmask", "report.json"));
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("no tokens here"));
    }

    @Test
    void verifyIsDispatchedAndRefusesTextThatIsNotADump(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("a.txt"), "{\"just\":\"json\"}");
        Files.writeString(dir.resolve("b.txt"), "{\"just\":\"json\"}");

        assertEquals(2, runIn(dir, "verify", "a.txt", "b.txt"));
    }

    @Test
    void verifyIsDispatchedAndFailsAnUnmaskedDump(@TempDir Path dir) throws IOException {
        String dump = """
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "pgto-worker-1" #15 prio=5 tid=0x1 nid=0x2 runnable
                   java.lang.Thread.State: RUNNABLE
                \tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:95)
                """;
        Files.writeString(dir.resolve("a.txt"), dump);
        Files.writeString(dir.resolve("b.txt"), dump);

        assertEquals(4, runIn(dir, "verify", "a.txt", "b.txt"));
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("FAIL"));
    }
}

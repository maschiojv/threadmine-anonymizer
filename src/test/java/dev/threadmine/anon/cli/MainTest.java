package dev.threadmine.anon.cli;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

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
}

package dev.threadmine.anon.cli;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {

    @Test
    void noArgumentsPrintsUsageAndReturnsUsageExitCode() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();

        int exit = Main.run(new String[]{}, new PrintStream(err, true, StandardCharsets.UTF_8));

        String usage = err.toString(StandardCharsets.UTF_8);
        assertEquals(1, exit);
        assertTrue(usage.contains("tm-anon"), "usage must mention the tool name");
        assertTrue(usage.contains("init"), "usage must list the init command");
        assertTrue(usage.contains("mask"), "usage must list the mask command");
        assertTrue(usage.contains("unmask"), "usage must list the unmask command");
        assertTrue(usage.contains("verify"), "usage must list the verify command");
    }

    @Test
    void unknownCommandPrintsUsageAndReturnsUsageExitCode() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();

        int exit = Main.run(new String[]{"frobnicate"}, new PrintStream(err, true, StandardCharsets.UTF_8));

        assertEquals(1, exit);
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("frobnicate"),
                "error must echo the unknown command");
    }
}

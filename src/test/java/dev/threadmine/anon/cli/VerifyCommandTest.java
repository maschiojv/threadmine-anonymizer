package dev.threadmine.anon.cli;

import dev.threadmine.anon.verify.AllowlistLookup;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifyCommandTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    /** Stands in for the 2E AllowlistMatcher: the JDK and Tomcat are public. */
    private static final AllowlistLookup ALLOWLIST = new AllowlistLookup() {
        private final List<String> packages = List.of("java.", "javax.", "jdk.", "sun.", "org.apache.");
        private final List<Pattern> threads = List.of(
                Pattern.compile("^http-nio-\\d+-exec-\\d+$"),
                Pattern.compile("^(Reference Handler|Finalizer|Attach Listener|VM Thread|main)$"));

        @Override
        public boolean allowsFqcn(String fqcnOrPackage) {
            return packages.stream().anyMatch(fqcnOrPackage::startsWith);
        }

        @Override
        public boolean allowsThreadName(String name) {
            return threads.stream().anyMatch(p -> p.matcher(name).matches());
        }
    };

    private static final String ORIGINAL = """
            Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode, sharing):

            "pgto-worker-1" #15 prio=5 tid=0x1 nid=0x2 runnable
               java.lang.Thread.State: RUNNABLE
            \tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:95)
            \tat java.lang.Thread.run(java.base@17.0.8/Thread.java:833)

            "http-nio-8080-exec-1" #18 daemon prio=5 tid=0x3 nid=0x4 runnable
               java.lang.Thread.State: RUNNABLE
            \tat org.apache.tomcat.util.threads.TaskQueue.poll(TaskQueue.java:99)
            """;

    private static final String MASKED = """
            # tm-anon v1
            Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode, sharing):

            "t1a2b3xc4d5e-1" #15 prio=5 tid=0x1 nid=0x2 runnable
               java.lang.Thread.State: RUNNABLE
            \tat p11111x11111.Caaaaaxbbbbb.mcccccxddddd(Caaaaaxbbbbb.java:95)
            \tat java.lang.Thread.run(java.base@17.0.8/Thread.java:833)

            "http-nio-8080-exec-1" #18 daemon prio=5 tid=0x3 nid=0x4 runnable
               java.lang.Thread.State: RUNNABLE
            \tat org.apache.tomcat.util.threads.TaskQueue.poll(TaskQueue.java:99)
            """;

    private int run(Path dir, String... args) {
        return VerifyCommand.execute(args, dir,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8),
                ALLOWLIST, true);
    }

    private String stdout() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    private void writePair(Path dir, String original, String masked) throws IOException {
        Files.writeString(dir.resolve("dump.txt"), original, StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("dump.anon.txt"), masked, StandardCharsets.UTF_8);
    }

    private void writeVault(Path dir, String... tokens) throws IOException {
        StringBuilder map = new StringBuilder();
        for (int i = 0; i < tokens.length; i++) {
            map.append("    \"").append(tokens[i]).append("\": \"original-").append(i).append('"');
            map.append(i < tokens.length - 1 ? ",\n" : "\n");
        }
        Files.writeString(dir.resolve("tm-anon-vault.json"), """
                {
                  "version": 1,
                  "createdAt": "2026-07-24T12:00:00Z",
                  "key": "%s",
                  "map": {
                %s  },
                  "collisions": {}
                }
                """.formatted("A".repeat(43) + "=", map), StandardCharsets.UTF_8);
    }

    // --- pass --------------------------------------------------------------

    @Test
    void aCompliantPairPassesWithExitZero(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);

        int exit = run(dir, "dump.txt", "dump.anon.txt");

        assertEquals(0, exit, stdout() + stderr());
        assertTrue(stdout().contains("PASS"), stdout());
        assertTrue(stdout().contains("Residual identifiers (must be 0): 0"), stdout());
        assertTrue(stdout().contains("all intact"), stdout());
        assertTrue(stdout().contains("threads:     2 -> 2"), stdout());
    }

    @Test
    void runsWithoutAVaultAndSaysSo(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);

        assertEquals(0, run(dir, "dump.txt", "dump.anon.txt"));
        assertTrue(stdout().contains("skipping the token/vault cross-check"), stdout());
    }

    @Test
    void usesTheDefaultVaultToFlagTokensItCannotReverse(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);
        writeVault(dir, "t1a2b3xc4d5e");

        int exit = run(dir, "dump.txt", "dump.anon.txt");

        assertEquals(0, exit, "an unknown token is a note, not a compliance failure");
        assertTrue(stdout().contains("unknown to this vault"), stdout());
        assertTrue(stdout().contains("Caaaaaxbbbbb"), stdout());
    }

    // --- fail (exit 4) -----------------------------------------------------

    @Test
    void aSurvivingIdentifierFailsWithExitFour(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED.replace(
                "\tat p11111x11111.Caaaaaxbbbbb.mcccccxddddd(Caaaaaxbbbbb.java:95)",
                "\tat com.acme.payment.LedgerService.applyEntry(LedgerService.java:95)"));

        int exit = run(dir, "dump.txt", "dump.anon.txt");

        assertEquals(4, exit);
        assertTrue(stdout().contains("FAIL"), stdout());
        assertTrue(stdout().contains("com.acme.payment.LedgerService.applyEntry"), stdout());
        assertTrue(stdout().contains("FRAME_CLASS"), stdout());
    }

    @Test
    void aBrokenStructuralAnchorFailsWithExitFour(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED.replace(
                "Full thread dump OpenJDK 64-Bit Server VM (17.0.8+7-LTS mixed mode, sharing):",
                "# [tm-anon: redacted]"));

        int exit = run(dir, "dump.txt", "dump.anon.txt");

        assertEquals(4, exit);
        assertTrue(stdout().contains("Full thread dump"), stdout());
        assertTrue(stdout().contains("1 in original, 0 in masked"), stdout());
        assertTrue(stdout().contains("Redacted lines: 1"), stdout());
    }

    @Test
    void aLostThreadFailsWithExitFourAndShowsTheMismatch(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED.replace(
                "\"http-nio-8080-exec-1\" #18 daemon prio=5 tid=0x3 nid=0x4 runnable\n", ""));

        int exit = run(dir, "dump.txt", "dump.anon.txt");

        assertEquals(4, exit);
        assertTrue(stdout().contains("MISMATCH"), stdout());
        assertTrue(stdout().contains("threads:     2 -> 1"), stdout());
    }

    // --- refused input (exit 2) -------------------------------------------

    @Test
    void textThatIsNotAThreadDumpIsRefused(@TempDir Path dir) throws IOException {
        writePair(dir, "{\"just\": \"json\"}", MASKED);

        int exit = run(dir, "dump.txt", "dump.anon.txt");

        assertEquals(2, exit);
        assertTrue(stderr().contains("not a recognizable thread dump"), stderr());
    }

    @Test
    void aMissingFileIsRefused(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("dump.txt"), ORIGINAL);

        assertEquals(2, run(dir, "dump.txt", "absent.anon.txt"));
        assertTrue(stderr().contains("absent.anon.txt"), stderr());
    }

    // --- vault problems (exit 3) ------------------------------------------

    @Test
    void anExplicitVaultThatDoesNotExistIsAVaultError(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);

        int exit = run(dir, "dump.txt", "dump.anon.txt", "--vault", "absent.vault.json");

        assertEquals(3, exit);
        assertTrue(stderr().contains("tm-anon init"), stderr());
    }

    @Test
    void aCorruptVaultIsAVaultError(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);
        Files.writeString(dir.resolve("tm-anon-vault.json"), "{ not json");

        assertEquals(3, run(dir, "dump.txt", "dump.anon.txt"));
    }

    // --- usage (exit 1) ----------------------------------------------------

    @Test
    void oneFileIsAUsageError(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);

        assertEquals(1, run(dir, "dump.txt"));
        assertTrue(stderr().contains("two files"), stderr());
    }

    @Test
    void threeFilesIsAUsageError(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);

        assertEquals(1, run(dir, "dump.txt", "dump.anon.txt", "extra.txt"));
    }

    // --- allowlist wiring --------------------------------------------------

    @Test
    void warnsLoudlyWhenTheAllowlistModuleIsNotInTheBuild(@TempDir Path dir) throws IOException {
        writePair(dir, ORIGINAL, MASKED);

        int exit = VerifyCommand.execute(new String[]{"dump.txt", "dump.anon.txt"}, dir,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8),
                ALLOWLIST, false);

        assertEquals(0, exit);
        assertTrue(stderr().contains("allowlist module is not part of this build"), stderr());
    }

    @Test
    void withTheRealAllowlistJdkFramesCountAsPublicInfrastructure(@TempDir Path dir) throws IOException {
        // Wired since the 2E merge: the bundled allowlist-v1 recognizes JDK frames,
        // so a properly masked dump passes instead of tripping fail-closed noise.
        writePair(dir, ORIGINAL, MASKED);

        int exit = VerifyCommand.execute(new String[]{"dump.txt", "dump.anon.txt"}, dir,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8),
                AllowlistBridge.fromClasspath(), AllowlistBridge.AVAILABLE);

        assertEquals(0, exit, stdout());
    }
}

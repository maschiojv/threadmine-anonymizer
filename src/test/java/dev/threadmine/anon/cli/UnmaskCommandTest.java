package dev.threadmine.anon.cli;

import dev.threadmine.anon.format.json.Json;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnmaskCommandTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(Path dir, String... args) {
        return UnmaskCommand.execute(args, dir,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private String stdout() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    /** A vault holding one thread token and one class token. */
    private void writeVault(Path dir) throws IOException {
        Files.writeString(dir.resolve("tm-anon-vault.json"), """
                {
                  "version": 1,
                  "createdAt": "2026-07-24T12:00:00Z",
                  "key": "%s",
                  "map": {
                    "t1a2b3xc4d5e": "pgto-worker-1",
                    "Caaaaaxbbbbb": "com.acme.payment.LedgerService"
                  },
                  "collisions": {}
                }
                """.formatted("A".repeat(43) + "="), StandardCharsets.UTF_8);
    }

    /** A vault whose originals carry the characters that used to corrupt JSON output. */
    private void writeHostileVault(Path dir) throws IOException {
        // In a text block "\\\\" produces the two characters \\ , which is how a
        // single backslash has to be written inside the vault's JSON.
        Files.writeString(dir.resolve("tm-anon-vault.json"), """
                {
                  "version": 1,
                  "createdAt": "2026-07-24T12:00:00Z",
                  "key": "%s",
                  "map": {
                    "t1a2b3xc4d5e": "win\\\\path\\\\worker-1",
                    "t9f8e7xd6c5b": "worker</script>"
                  },
                  "collisions": {}
                }
                """.formatted("A".repeat(43) + "="), StandardCharsets.UTF_8);
    }

    @Test
    void writesTheUnmaskedTextToStdoutWhenNoOutputFileIsGiven(@TempDir Path dir) throws IOException {
        writeVault(dir);
        Files.writeString(dir.resolve("report.json"), "{\"thread\":\"t1a2b3xc4d5e\"}");

        int exit = run(dir, "report.json");

        assertEquals(0, exit, stderr());
        assertEquals("{\"thread\":\"pgto-worker-1\"}", stdout());
        assertTrue(stderr().contains("1"), "the summary belongs on stderr so stdout stays pipeable");
    }

    @Test
    void writesToTheOutputFileAndKeepsStdoutForTheSummary(@TempDir Path dir) throws IOException {
        writeVault(dir);
        Files.writeString(dir.resolve("report.json"), "at Caaaaaxbbbbb in t1a2b3xc4d5e");

        int exit = run(dir, "report.json", "-o", "plain.json");

        assertEquals(0, exit, stderr());
        assertEquals("at LedgerService in pgto-worker-1",
                Files.readString(dir.resolve("plain.json"), StandardCharsets.UTF_8));
        assertTrue(stdout().contains("plain.json"), stdout());
        assertTrue(stdout().contains("2"), "summary must count both restored tokens: " + stdout());
    }

    @Test
    void preservesTheInputByteForByteWhenThereIsNothingToUnmask(@TempDir Path dir) throws IOException {
        writeVault(dir);
        String content = "line one\r\nline two\n\nno tokens at all\n";
        Files.writeString(dir.resolve("plain.txt"), content);

        assertEquals(0, run(dir, "plain.txt"));
        assertEquals(content, stdout());
    }

    @Test
    void unknownTokensAreAWarningNotAFailure(@TempDir Path dir) throws IOException {
        writeVault(dir);
        Files.writeString(dir.resolve("report.json"), "t1a2b3xc4d5e and C00000x11111 and C00000x11111");

        int exit = run(dir, "report.json");

        assertEquals(0, exit, "unmask never fails because of an unknown token");
        assertEquals("pgto-worker-1 and C00000x11111 and C00000x11111", stdout());
        assertTrue(stderr().toLowerCase().contains("warning"), stderr());
        assertTrue(stderr().contains("C00000x11111"), "the unknown token must be named: " + stderr());
        assertTrue(stderr().toLowerCase().contains("vault"), "the warning must point at the likely cause");
    }

    @Test
    void honoursAnExplicitVaultPath(@TempDir Path dir) throws IOException {
        writeVault(dir);
        Files.move(dir.resolve("tm-anon-vault.json"), dir.resolve("team-a.vault.json"));
        Files.writeString(dir.resolve("report.json"), "t1a2b3xc4d5e");

        assertEquals(0, run(dir, "report.json", "--vault", "team-a.vault.json"), stderr());
        assertEquals("pgto-worker-1", stdout());
    }

    // --- output format -----------------------------------------------------

    @Test
    void infersJsonFromTheInputExtensionAndKeepsTheOutputParseable(@TempDir Path dir) throws IOException {
        writeHostileVault(dir);
        Files.writeString(dir.resolve("export.json"), "{\"nome\":\"t1a2b3xc4d5e\"}");

        int exit = run(dir, "export.json");

        assertEquals(0, exit, stderr());
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = (Map<String, Object>) Json.parse(stdout());
        assertEquals("win\\path\\worker-1", parsed.get("nome"));
    }

    @Test
    void theExplicitFlagOverridesTheInferredFormat(@TempDir Path dir) throws IOException {
        writeHostileVault(dir);
        Files.writeString(dir.resolve("export.json"), "{\"nome\":\"t1a2b3xc4d5e\"}");

        int exit = run(dir, "export.json", "--format", "text");

        assertEquals(0, exit, stderr());
        // Forced to text: the raw backslash lands in the output and breaks the JSON.
        assertEquals("{\"nome\":\"win\\path\\worker-1\"}", stdout());
    }

    @Test
    void htmlIsInferredAndKeepsAClosingScriptTagOutOfTheOutput(@TempDir Path dir) throws IOException {
        writeHostileVault(dir);
        Files.writeString(dir.resolve("report.html"), "{\"nome\":\"t9f8e7xd6c5b\"}");

        int exit = run(dir, "report.html");

        assertEquals(0, exit, stderr());
        assertFalse(stdout().contains("</script>"), stdout());
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = (Map<String, Object>) Json.parse(stdout());
        assertEquals("worker</script>", parsed.get("nome"));
    }

    @Test
    void anUnknownFormatIsAUsageError(@TempDir Path dir) throws IOException {
        writeHostileVault(dir);
        Files.writeString(dir.resolve("dump.txt"), "t1a2b3xc4d5e");

        int exit = run(dir, "dump.txt", "--format", "yaml");

        assertEquals(1, exit, "an unknown format must not silently fall back");
        assertTrue(stderr().contains("--format"), stderr());
    }

    // --- exit codes --------------------------------------------------------

    @Test
    void missingVaultIsAVaultErrorWithAPointerToInit(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("report.json"), "t1a2b3xc4d5e");

        int exit = run(dir, "report.json");

        assertEquals(3, exit);
        assertTrue(stderr().contains("tm-anon init"), "a missing vault must suggest init: " + stderr());
    }

    @Test
    void corruptVaultIsAVaultError(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("tm-anon-vault.json"), "{ not json");
        Files.writeString(dir.resolve("report.json"), "t1a2b3xc4d5e");

        assertEquals(3, run(dir, "report.json"));
    }

    @Test
    void missingInputFileIsAnInputError(@TempDir Path dir) throws IOException {
        writeVault(dir);

        int exit = run(dir, "absent.json");

        assertEquals(2, exit);
        assertTrue(stderr().contains("absent.json"), stderr());
    }

    @Test
    void anUnwritableOutputPathIsAnInputError(@TempDir Path dir) throws IOException {
        writeVault(dir);
        Files.writeString(dir.resolve("report.json"), "t1a2b3xc4d5e");
        Files.writeString(dir.resolve("blocker"), "not a directory");

        int exit = run(dir, "report.json", "-o", "blocker/out.json");

        assertEquals(2, exit);
        assertFalse(stderr().isEmpty(), "the failure must be explained");
    }

    @Test
    void noInputFileIsAUsageError(@TempDir Path dir) throws IOException {
        writeVault(dir);

        assertEquals(1, run(dir));
    }

    @Test
    void moreThanOneInputFileIsAUsageError(@TempDir Path dir) throws IOException {
        writeVault(dir);
        Files.writeString(dir.resolve("a.json"), "x");
        Files.writeString(dir.resolve("b.json"), "y");

        assertEquals(1, run(dir, "a.json", "b.json"));
    }

    @Test
    void anUnknownOptionIsAUsageError(@TempDir Path dir) throws IOException {
        writeVault(dir);
        Files.writeString(dir.resolve("a.json"), "x");

        assertEquals(1, run(dir, "a.json", "--strict"));
    }
}

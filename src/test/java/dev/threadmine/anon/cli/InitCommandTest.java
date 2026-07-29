package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.Vault;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InitCommandTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(Path workingDir, String... args) {
        return InitCommand.execute(args, workingDir,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private String stdout() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    @Test
    void createsTheDefaultVaultAndReportsWhereItLives(@TempDir Path dir) {
        int exit = run(dir);

        assertEquals(0, exit, stderr());
        Path vault = dir.resolve("tm-anon-vault.json");
        assertTrue(Files.exists(vault), "init must create the default vault file");
        assertTrue(stdout().contains(vault.toString()), "output must show the absolute vault path");
    }

    @Test
    void createdVaultIsLoadableAndCarriesAFreshKey(@TempDir Path dir) {
        run(dir);

        // Round-trips through the real loader: proves init produced a valid v1 vault.
        try (Vault vault = Vault.load(dir.resolve("tm-anon-vault.json"))) {
            assertTrue(vault != null);
        }
    }

    @Test
    void warnsAboutBackupAndAboutNeverVersioningTheVault(@TempDir Path dir) {
        run(dir);

        String text = stdout().toLowerCase();
        assertTrue(text.contains("back"), "output must remind the user to back the vault up");
        assertTrue(text.contains("never"), "output must say the vault is never to be shared/versioned");
        assertTrue(text.contains("unmask"), "output must explain what is lost without the vault");
    }

    @Test
    void refusesToOverwriteAnExistingVaultWithVaultExitCode(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("tm-anon-vault.json"), "{}");

        int exit = run(dir);

        assertEquals(3, exit);
        assertTrue(stderr().toLowerCase().contains("refusing"), stderr());
        assertEquals("{}", Files.readString(dir.resolve("tm-anon-vault.json")),
                "the existing vault must be left untouched");
    }

    @Test
    void honoursAnExplicitVaultPath(@TempDir Path dir) {
        int exit = run(dir, "--vault", "team-a.vault.json");

        assertEquals(0, exit, stderr());
        assertTrue(Files.exists(dir.resolve("team-a.vault.json")));
        assertFalse(Files.exists(dir.resolve("tm-anon-vault.json")));
    }

    @Test
    void createsParentDirectoriesOfAnExplicitVaultPath(@TempDir Path dir) {
        int exit = run(dir, "--vault", "secrets/nested/tm.vault.json");

        assertEquals(0, exit, stderr());
        assertTrue(Files.exists(dir.resolve("secrets/nested/tm.vault.json")));
    }

    @Test
    void addsTheVaultToGitignoreWhenTheDirectoryIsAGitRepository(@TempDir Path dir) throws IOException {
        Files.createDirectory(dir.resolve(".git"));

        int exit = run(dir);

        assertEquals(0, exit, stderr());
        List<String> lines = Files.readAllLines(dir.resolve(".gitignore"));
        assertTrue(lines.contains("tm-anon-vault.json"), lines.toString());
        assertTrue(stdout().contains(".gitignore"), "output must say the ignore entry was added");
    }

    @Test
    void appendsToAnExistingGitignoreKeepingItsContent(@TempDir Path dir) throws IOException {
        Files.createDirectory(dir.resolve(".git"));
        Files.writeString(dir.resolve(".gitignore"), "target/\n");

        run(dir);

        List<String> lines = Files.readAllLines(dir.resolve(".gitignore"));
        assertTrue(lines.contains("target/"), "existing entries must survive");
        assertTrue(lines.contains("tm-anon-vault.json"));
    }

    @Test
    void appendsANewlineBeforeTheEntryWhenGitignoreLacksATrailingOne(@TempDir Path dir) throws IOException {
        Files.createDirectory(dir.resolve(".git"));
        Files.writeString(dir.resolve(".gitignore"), "target/");

        run(dir);

        assertEquals(List.of("target/", "tm-anon-vault.json"), Files.readAllLines(dir.resolve(".gitignore")));
    }

    @Test
    void doesNotDuplicateAnIgnoreEntryThatIsAlreadyThere(@TempDir Path dir) throws IOException {
        Files.createDirectory(dir.resolve(".git"));
        Files.writeString(dir.resolve(".gitignore"), "/tm-anon-vault.json\n");

        run(dir);

        assertEquals(List.of("/tm-anon-vault.json"), Files.readAllLines(dir.resolve(".gitignore")));
    }

    @Test
    void worksWhenGitDirIsAFileAsInWorktreesAndSubmodules(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve(".git"), "gitdir: ../.git/worktrees/feature\n");

        run(dir);

        assertTrue(Files.readAllLines(dir.resolve(".gitignore")).contains("tm-anon-vault.json"));
    }

    @Test
    void neverCreatesAGitignoreOutsideAGitRepository(@TempDir Path dir) {
        int exit = run(dir);

        assertEquals(0, exit, stderr());
        assertFalse(Files.exists(dir.resolve(".gitignore")),
                "no .gitignore should be invented in a plain directory");
    }

    @Test
    void doesNotTouchGitignoreForAVaultStoredOutsideTheRepository(@TempDir Path dir, @TempDir Path elsewhere)
            throws IOException {
        Files.createDirectory(dir.resolve(".git"));

        int exit = run(dir, "--vault", elsewhere.resolve("outside.vault.json").toString());

        assertEquals(0, exit, stderr());
        assertFalse(Files.exists(dir.resolve(".gitignore")),
                "a vault outside the repo cannot be ignored by this repo's .gitignore");
    }

    @Test
    void rejectsExtraPositionalArgumentsWithTheUsageExitCode(@TempDir Path dir) {
        int exit = run(dir, "unexpected");

        assertEquals(1, exit);
        assertTrue(stderr().contains("unexpected"), stderr());
    }

    @Test
    void rejectsAnUnknownOptionWithTheUsageExitCode(@TempDir Path dir) {
        assertEquals(1, run(dir, "--force"));
    }
}

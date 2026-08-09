package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenType;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.core.VaultException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** CLI side of vault encryption: {@code init --encrypt} and opening what it wrote. */
class EncryptedVaultCliTest {

    @TempDir
    Path tempDir;

    private final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    private final PrintStream out = new PrintStream(outBytes, true, StandardCharsets.UTF_8);
    private final PrintStream err = new PrintStream(errBytes, true, StandardCharsets.UTF_8);

    private String out() {
        return outBytes.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return errBytes.toString(StandardCharsets.UTF_8);
    }

    /** Stands in for the environment variable / terminal prompt. */
    private static PassphraseSource supplying(String value) {
        return new PassphraseSource() {
            @Override
            public char[] existing() {
                return value == null ? null : value.toCharArray();
            }

            @Override
            public char[] fresh() {
                return value == null ? null : value.toCharArray();
            }
        };
    }

    @Test
    void initWithEncryptCreatesAVaultOnlyThePassphraseOpens() {
        Path vault = tempDir.resolve("v.json");
        int code = InitCommand.execute(new String[]{"--vault", vault.toString(), "--encrypt"},
                tempDir, out, err, supplying("hunter2-but-longer"));

        assertEquals(ExitCodes.OK, code, err());
        assertTrue(Vault.isEncrypted(vault), "the created vault must be encrypted");
        assertTrue(out().contains("(encrypted)"), out());
        assertTrue(out().toLowerCase().contains("no recovery"),
                "losing the passphrase is unrecoverable and the user must be told: " + out());

        try (Vault opened = Commands.openVault(vault, supplying("hunter2-but-longer"))) {
            assertEquals("com.acme.Foo",
                    new HmacTokenEngine(opened).resolve(
                            new HmacTokenEngine(opened).tokenize(TokenType.CLASS_NAME, "com.acme.Foo"))
                            .orElseThrow());
        }
    }

    @Test
    void initWithoutEncryptStillCreatesAPlaintextVaultAndSaysSo() {
        Path vault = tempDir.resolve("v.json");
        int code = InitCommand.execute(new String[]{"--vault", vault.toString()},
                tempDir, out, err, supplying(null));

        assertEquals(ExitCodes.OK, code, err());
        assertFalse(Vault.isEncrypted(vault));
        assertTrue(out().contains("--encrypt"), "the plaintext path should point at the safer one: " + out());
    }

    @Test
    void initWithEncryptFailsCleanlyWhenNoPassphraseIsAvailable() {
        Path vault = tempDir.resolve("v.json");
        int code = InitCommand.execute(new String[]{"--vault", vault.toString(), "--encrypt"},
                tempDir, out, err, supplying(null));

        assertEquals(ExitCodes.VAULT_ERROR, code);
        assertTrue(err().contains(PassphraseSource.ENV_VAR), err());
        assertFalse(Files.exists(vault), "a half-created vault would be worse than none");
    }

    @Test
    void openingAnEncryptedVaultWithTheWrongPassphraseFails() {
        Path vault = tempDir.resolve("v.json");
        InitCommand.execute(new String[]{"--vault", vault.toString(), "--encrypt"},
                tempDir, out, err, supplying("right passphrase"));

        assertThrows(VaultException.class,
                () -> Commands.openVault(vault, supplying("wrong passphrase")));
    }

    @Test
    void openingAnEncryptedVaultWithNoPassphraseAvailableExplainsHow() {
        Path vault = tempDir.resolve("v.json");
        InitCommand.execute(new String[]{"--vault", vault.toString(), "--encrypt"},
                tempDir, out, err, supplying("a passphrase"));

        VaultException e = assertThrows(VaultException.class,
                () -> Commands.openVault(vault, supplying(null)));
        assertTrue(e.getMessage().contains(PassphraseSource.ENV_VAR), e.getMessage());
    }

    @Test
    void maskAgainstAnEncryptedVaultFailsWithVaultExitCodeWhenNoPassphraseIsReachable() throws IOException {
        // The end-to-end path through Main, which uses the standard source:
        // no terminal in a test JVM, so the passphrase must be unreachable.
        assumeTrue(System.getenv(PassphraseSource.ENV_VAR) == null,
                "this test needs the passphrase environment variable unset");
        assumeTrue(System.console() == null, "this test needs a non-interactive JVM");

        Path vault = tempDir.resolve("v.json");
        InitCommand.execute(new String[]{"--vault", vault.toString(), "--encrypt"},
                tempDir, out, err, supplying("a passphrase"));
        Path dump = tempDir.resolve("dump.txt");
        Files.writeString(dump, """
                Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode):

                "pgto-worker-1" #24 prio=5 tid=0x1 nid=0x1 runnable
                   java.lang.Thread.State: RUNNABLE
                """, StandardCharsets.UTF_8);

        int code = Main.run(new String[]{"mask", dump.toString(), "--vault", vault.toString()},
                tempDir, out, err);

        assertEquals(ExitCodes.VAULT_ERROR, code, out() + err());
        assertTrue(err().toLowerCase().contains("encrypted"), err());
    }

    @Test
    void plaintextVaultsNeverAskForAPassphrase() {
        // The common case must stay non-interactive: a source that would blow
        // up if consulted proves openVault does not consult it.
        Path vault = tempDir.resolve("v.json");
        InitCommand.execute(new String[]{"--vault", vault.toString()}, tempDir, out, err, supplying(null));

        PassphraseSource exploding = new PassphraseSource() {
            @Override
            public char[] existing() {
                throw new AssertionError("a plaintext vault must not trigger a passphrase prompt");
            }

            @Override
            public char[] fresh() {
                throw new AssertionError("a plaintext vault must not trigger a passphrase prompt");
            }
        };
        Commands.openVault(vault, exploding).close();
    }
}

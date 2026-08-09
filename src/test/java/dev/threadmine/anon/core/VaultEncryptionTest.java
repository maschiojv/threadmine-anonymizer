package dev.threadmine.anon.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SPEC §2: passphrase encryption for the vault.
 *
 * <p>The vault is the whole secret — the HMAC key plus the token dictionary.
 * Backing it up (which the tool tells users to do) means the plaintext file
 * ends up on a second disk, in a cloud sync folder, or on a USB stick, and at
 * that point "never share it" stops being enforceable. Encrypting at rest is
 * what makes a stolen vault file useless without the passphrase.</p>
 */
class VaultEncryptionTest {

    @TempDir
    Path tempDir;

    private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

    private static char[] passphrase() {
        return PASSPHRASE.clone();
    }

    private String read(Path file) throws IOException {
        return Files.readString(file, StandardCharsets.UTF_8);
    }

    @Test
    void encryptedVaultRoundTripsThroughSaveAndLoad() {
        Path file = tempDir.resolve("vault.json");
        String token;
        try (Vault vault = Vault.create(file, passphrase())) {
            token = new HmacTokenEngine(vault).tokenize(TokenType.CLASS_NAME, "com.acme.billing.InvoiceService");
        }

        try (Vault reopened = Vault.load(file, passphrase())) {
            assertEquals("com.acme.billing.InvoiceService",
                    new HmacTokenEngine(reopened).resolve(token).orElseThrow());
        }
    }

    @Test
    void tokensStayIdenticalAcrossReopens() {
        Path file = tempDir.resolve("vault.json");
        String first;
        try (Vault vault = Vault.create(file, passphrase())) {
            first = new HmacTokenEngine(vault).tokenize(TokenType.THREAD_NAME, "pgto-worker");
        }
        try (Vault reopened = Vault.load(file, passphrase())) {
            // Same key, same canonical value: determinism must survive encryption.
            assertEquals(first, new HmacTokenEngine(reopened).tokenize(TokenType.THREAD_NAME, "pgto-worker"));
        }
    }

    @Test
    void encryptedFileRevealsNeitherTheKeyNorAnyOriginal() throws IOException {
        Path encrypted = tempDir.resolve("encrypted.json");
        String actualKey;
        try (Vault vault = Vault.create(encrypted, passphrase())) {
            new HmacTokenEngine(vault).tokenize(TokenType.CLASS_NAME, "com.acme.billing.InvoiceService");
            vault.save();
            // Same package as Vault, so this is the real key the file protects,
            // not a stand-in that would pass the assertion for free.
            actualKey = java.util.Base64.getEncoder().encodeToString(vault.key());
        }

        String onDisk = read(encrypted);
        assertFalse(onDisk.contains("com.acme.billing.InvoiceService"),
                "an original name must never be readable in an encrypted vault");
        assertFalse(onDisk.contains("InvoiceService"));
        assertFalse(onDisk.contains(actualKey), "the HMAC key must not appear in the clear");
        assertFalse(onDisk.contains("\"map\""), "the dictionary must live inside the ciphertext");
        assertTrue(onDisk.contains("\"payload\""));
    }

    @Test
    void plaintextVaultStillStoresTheKeyInTheClear() throws IOException {
        // The contrast that gives the test above its meaning: v1 really does
        // put the key on disk, which is exactly what encryption is fixing.
        Path plain = tempDir.resolve("plain.json");
        try (Vault vault = Vault.create(plain)) {
            assertTrue(read(plain).contains(java.util.Base64.getEncoder().encodeToString(vault.key())));
        }
    }

    @Test
    void wrongPassphraseIsRejected() {
        Path file = tempDir.resolve("vault.json");
        try (Vault vault = Vault.create(file, passphrase())) {
            new HmacTokenEngine(vault).tokenize(TokenType.CLASS_NAME, "com.acme.Foo");
        }
        VaultException e = assertThrows(VaultException.class,
                () -> Vault.load(file, "wrong passphrase".toCharArray()));
        assertTrue(e.getMessage().toLowerCase().contains("passphrase"),
                "the message must name the passphrase, not leak a crypto stack trace: " + e.getMessage());
    }

    @Test
    void encryptedVaultCannotBeOpenedWithoutAPassphrase() {
        Path file = tempDir.resolve("vault.json");
        Vault.create(file, passphrase()).close();

        VaultException e = assertThrows(VaultException.class, () -> Vault.load(file));
        assertTrue(e.getMessage().toLowerCase().contains("encrypted"),
                "the message must say the vault is encrypted: " + e.getMessage());
        assertTrue(Vault.isEncrypted(file), "callers need to detect this before prompting");
    }

    @Test
    void plaintextVaultIsStillSupportedAndDetectedAsSuch() {
        Path file = tempDir.resolve("vault.json");
        String token;
        try (Vault vault = Vault.create(file)) {
            token = new HmacTokenEngine(vault).tokenize(TokenType.CLASS_NAME, "com.acme.Foo");
        }
        assertFalse(Vault.isEncrypted(file));
        try (Vault reopened = Vault.load(file)) {
            assertEquals("com.acme.Foo", new HmacTokenEngine(reopened).resolve(token).orElseThrow());
        }
    }

    @Test
    void passingAPassphraseToAPlaintextVaultIsRefused() {
        // Silently ignoring it would leave the user believing the file is
        // encrypted when it is not.
        Path file = tempDir.resolve("vault.json");
        Vault.create(file).close();
        assertThrows(VaultException.class, () -> Vault.load(file, passphrase()));
    }

    @Test
    void everySaveUsesAFreshNonce() throws IOException {
        Path file = tempDir.resolve("vault.json");
        try (Vault vault = Vault.create(file, passphrase())) {
            String firstNonce = field(read(file), "nonce");
            new HmacTokenEngine(vault).tokenize(TokenType.CLASS_NAME, "com.acme.Foo");
            vault.save();
            String secondNonce = field(read(file), "nonce");
            // Reusing a nonce under the same GCM key destroys confidentiality
            // outright; this is the one crypto mistake that must never happen.
            assertNotEquals(firstNonce, secondNonce);
        }
    }

    @Test
    void tamperedCiphertextIsRejected() throws IOException {
        Path file = tempDir.resolve("vault.json");
        try (Vault vault = Vault.create(file, passphrase())) {
            new HmacTokenEngine(vault).tokenize(TokenType.CLASS_NAME, "com.acme.Foo");
        }
        String content = read(file);
        String payload = field(content, "payload");
        String flipped = (payload.charAt(0) == 'A' ? "B" : "A") + payload.substring(1);
        Files.writeString(file, content.replace(payload, flipped), StandardCharsets.UTF_8);

        assertThrows(VaultException.class, () -> Vault.load(file, passphrase()));
    }

    @Test
    void tamperedKdfParametersAreRejected() throws IOException {
        // The KDF block is authenticated as associated data: an attacker who
        // can edit the file must not be able to weaken it to 1 iteration and
        // have the vault still open.
        Path file = tempDir.resolve("vault.json");
        Vault.create(file, passphrase()).close();
        String content = read(file);
        assertTrue(content.contains("\"iterations\""));
        Files.writeString(file, content.replaceAll("\"iterations\": \\d+", "\"iterations\": 1"),
                StandardCharsets.UTF_8);

        assertThrows(VaultException.class, () -> Vault.load(file, passphrase()));
    }

    @Test
    void anEmptyPassphraseIsRefusedAtCreation() {
        assertThrows(VaultException.class,
                () -> Vault.create(tempDir.resolve("vault.json"), new char[0]));
    }

    private static String keyField(String json) {
        return field(json, "key");
    }

    private static String field(String json, String name) {
        int at = json.indexOf("\"" + name + "\"");
        assertTrue(at >= 0, "field " + name + " missing from " + json);
        int open = json.indexOf('"', json.indexOf(':', at) + 1);
        int close = json.indexOf('"', open + 1);
        return json.substring(open + 1, close);
    }
}

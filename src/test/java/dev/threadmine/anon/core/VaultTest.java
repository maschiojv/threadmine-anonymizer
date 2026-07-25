package dev.threadmine.anon.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VaultTest {

    @TempDir
    Path dir;

    private Path vaultFile() {
        return dir.resolve("tm-anon-vault.json");
    }

    @Test
    void createWritesFileWithFreshKeyVersionAndEmptyMap() throws IOException {
        try (Vault vault = Vault.create(vaultFile())) {
            assertTrue(Files.exists(vaultFile()), "create must persist the vault immediately");
            assertEquals(32, vault.key().length, "key must be 32 bytes");
        }

        Map<String, Object> json = MiniJson.parse(Files.readString(vaultFile()));
        assertEquals(1L, json.get("version"));
        assertEquals(32, Base64.getDecoder().decode((String) json.get("key")).length);
        assertTrue(json.get("createdAt") instanceof String s && !s.isBlank());
        assertEquals(Map.of(), json.get("map"));
        assertEquals(Map.of(), json.get("collisions"));
    }

    @Test
    void createRefusesToOverwriteAnExistingVault() throws IOException {
        Files.writeString(vaultFile(), "precious");

        assertThrows(VaultException.class, () -> Vault.create(vaultFile()),
                "overwriting an existing vault would destroy its key");
        assertEquals("precious", Files.readString(vaultFile()), "existing file must be untouched");
    }

    @Test
    void twoVaultsGetDifferentKeys() {
        try (Vault a = Vault.create(dir.resolve("a.json"));
             Vault b = Vault.create(dir.resolve("b.json"))) {
            assertFalse(java.util.Arrays.equals(a.key(), b.key()));
        }
    }

    @Test
    void saveLoadRoundTripPreservesKeyMapAndCollisions() {
        byte[] originalKey;
        try (Vault vault = Vault.create(vaultFile())) {
            originalKey = vault.key().clone();
            vault.put("C3f9c1x84d2b", "com.acme.billing.InvoiceService");
            vault.put("t9e2axb7f31", "pgto-worker");
            vault.put("t9e2a4f1xb7f3190c", "outra-coisa");
            vault.recordCollision("t9e2axb7f31", "outra-coisa", "t9e2a4f1xb7f3190c");
            vault.save();
        }

        try (Vault loaded = Vault.load(vaultFile())) {
            assertArrayEquals(originalKey, loaded.key());
            assertEquals("com.acme.billing.InvoiceService", loaded.getOriginal("C3f9c1x84d2b"));
            assertEquals("pgto-worker", loaded.getOriginal("t9e2axb7f31"));
            assertNull(loaded.getOriginal("m00000x00000"));
            Vault.CollisionEntry entry = loaded.collisions().get("t9e2axb7f31");
            assertEquals("outra-coisa", entry.original());
            assertEquals("t9e2a4f1xb7f3190c", entry.extendedToken());
        }
    }

    @Test
    void closeSavesPendingChanges() {
        try (Vault vault = Vault.create(vaultFile())) {
            vault.put("p11111x22222", "com.acme");
        }

        try (Vault loaded = Vault.load(vaultFile())) {
            assertEquals("com.acme", loaded.getOriginal("p11111x22222"));
        }
    }

    @Test
    void saveLeavesNoTemporaryFilesBehind() throws IOException {
        try (Vault vault = Vault.create(vaultFile())) {
            vault.put("p11111x22222", "com.acme");
            vault.save();
        }

        try (var files = Files.list(dir)) {
            assertEquals(List.of(vaultFile()), files.toList(),
                    "atomic save must leave only the vault file in place");
        }
    }

    @Test
    void loadRejectsMissingFile() {
        assertThrows(VaultException.class, () -> Vault.load(vaultFile()));
    }

    @Test
    void loadRejectsCorruptJson() throws IOException {
        Files.writeString(vaultFile(), "{ not json");
        assertThrows(VaultException.class, () -> Vault.load(vaultFile()));
    }

    @Test
    void loadRejectsUnknownVersion() throws IOException {
        Files.writeString(vaultFile(), """
                {"version": 99, "createdAt": "x", "key": "%s", "map": {}, "collisions": {}}
                """.formatted(Base64.getEncoder().encodeToString(new byte[32])));
        assertThrows(VaultException.class, () -> Vault.load(vaultFile()));
    }

    @Test
    void loadRejectsKeyOfWrongLength() throws IOException {
        Files.writeString(vaultFile(), """
                {"version": 1, "createdAt": "x", "key": "%s", "map": {}, "collisions": {}}
                """.formatted(Base64.getEncoder().encodeToString(new byte[16])));
        assertThrows(VaultException.class, () -> Vault.load(vaultFile()));
    }

    @Test
    void loadRejectsKeyThatIsNotBase64() throws IOException {
        Files.writeString(vaultFile(), """
                {"version": 1, "createdAt": "x", "key": "!!!not-base64!!!", "map": {}, "collisions": {}}
                """);
        assertThrows(VaultException.class, () -> Vault.load(vaultFile()));
    }

    @Test
    void putRejectsConflictingReRegistration() {
        try (Vault vault = Vault.create(vaultFile())) {
            vault.put("C3f9c1x84d2b", "com.acme.A");
            assertThrows(VaultException.class, () -> vault.put("C3f9c1x84d2b", "com.acme.B"),
                    "silently remapping a token would corrupt the unmask dictionary");
        }
    }
}

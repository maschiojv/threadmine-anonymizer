package dev.threadmine.anon.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Forces token collisions by injecting a fake digester whose first 5 bytes
 * (the standard 40-bit form) are identical for every value, while bytes 6-7
 * still distinguish values — exercising SPEC §1 "Colisão".
 */
class HmacTokenEngineCollisionTest {

    @TempDir
    Path dir;

    private Vault vault;
    private HmacTokenEngine engine;

    /** Same 40-bit prefix for everything; bytes 5-6 depend on the value. */
    private static final HmacTokenEngine.Digester COLLIDING_ON_STANDARD = (key, type, value) -> {
        byte[] digest = new byte[7];
        digest[5] = (byte) value.hashCode();
        digest[6] = (byte) (value.hashCode() >>> 8);
        return digest;
    };

    /** Identical digest for every value: even the extended form collides. */
    private static final HmacTokenEngine.Digester FULLY_COLLIDING = (key, type, value) -> new byte[7];

    @BeforeEach
    void setUp() {
        vault = Vault.create(dir.resolve("vault.json"));
        engine = new HmacTokenEngine(vault, COLLIDING_ON_STANDARD);
    }

    @Test
    void secondValueCollidingOnStandardFormGetsExtendedToken() {
        String first = engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");
        String second = engine.tokenize(TokenType.THREAD_NAME, "relatorio-worker");

        assertTrue(first.matches("t[0-9a-f]{5}x[0-9a-f]{5}"), "first keeps the standard form: " + first);
        assertTrue(second.matches("t[0-9a-f]{7}x[0-9a-f]{7}"), "second gets the extended form: " + second);
    }

    @Test
    void collisionIsRegisteredInTheVault() {
        String standard = engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");
        String extended = engine.tokenize(TokenType.THREAD_NAME, "relatorio-worker");

        Vault.CollisionEntry entry = vault.collisions().get(standard);
        assertEquals("relatorio-worker", entry.original());
        assertEquals(extended, entry.extendedToken());
    }

    @Test
    void collidedValueIsDeterministicFromThenOn() {
        engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");
        String extended = engine.tokenize(TokenType.THREAD_NAME, "relatorio-worker");

        assertEquals(extended, engine.tokenize(TokenType.THREAD_NAME, "relatorio-worker"));
        assertEquals(Optional.of("relatorio-worker"), engine.resolve(extended));
    }

    @Test
    void collisionSurvivesSaveAndReload() {
        String standard = engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");
        String extended = engine.tokenize(TokenType.THREAD_NAME, "relatorio-worker");
        vault.save();

        try (Vault reloaded = Vault.load(dir.resolve("vault.json"))) {
            HmacTokenEngine other = new HmacTokenEngine(reloaded, COLLIDING_ON_STANDARD);
            assertEquals(standard, other.tokenize(TokenType.THREAD_NAME, "pgto-worker"));
            assertEquals(extended, other.tokenize(TokenType.THREAD_NAME, "relatorio-worker"));
            assertEquals(extended, reloaded.collisions().get(standard).extendedToken());
        }
    }

    @Test
    void sameValueTwiceIsNotACollision() {
        engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");
        engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");

        assertTrue(vault.collisions().isEmpty());
    }

    @Test
    void collisionBeyondTheExtendedFormFailsLoudly() {
        // First value takes the standard form, second takes the extended form;
        // a third fully-colliding value has no distinct token left.
        HmacTokenEngine broken = new HmacTokenEngine(vault, FULLY_COLLIDING);
        broken.tokenize(TokenType.THREAD_NAME, "pgto-worker");
        broken.tokenize(TokenType.THREAD_NAME, "relatorio-worker");

        assertThrows(VaultException.class,
                () -> broken.tokenize(TokenType.THREAD_NAME, "estoque-worker"),
                "a full 56-bit collision must never be silently remapped");
    }
}

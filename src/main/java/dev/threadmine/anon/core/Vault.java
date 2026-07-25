package dev.threadmine.anon.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Local token vault: holds the HMAC key plus the token-to-original dictionary
 * used by unmask. The file must never leave the owner's machine — whoever has
 * the vault can reverse every token.
 */
public final class Vault implements AutoCloseable {

    private static final int VERSION = 1;
    private static final int KEY_LENGTH_BYTES = 32;

    private final Path file;
    private final byte[] key;
    private final String createdAt;
    private final Map<String, String> map;
    private final Map<String, CollisionEntry> collisions;
    private boolean dirty;

    private Vault(Path file, byte[] key, String createdAt,
                  Map<String, String> map, Map<String, CollisionEntry> collisions) {
        this.file = file;
        this.key = key;
        this.createdAt = createdAt;
        this.map = map;
        this.collisions = collisions;
    }

    /** Creates a new vault with a fresh random 256-bit key and persists it immediately. */
    public static Vault create(Path file) {
        if (Files.exists(file)) {
            throw new VaultException("vault already exists, refusing to overwrite (its key would be lost): " + file);
        }
        byte[] key = new byte[KEY_LENGTH_BYTES];
        new SecureRandom().nextBytes(key);
        Vault vault = new Vault(file, key, Instant.now().toString(),
                new LinkedHashMap<>(), new LinkedHashMap<>());
        vault.save();
        return vault;
    }

    /** Loads an existing vault, validating version and key material. */
    public static Vault load(Path file) {
        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new VaultException("cannot read vault file: " + file, e);
        }
        Map<String, Object> json;
        try {
            json = MiniJson.parse(content);
        } catch (MiniJson.ParseException e) {
            throw new VaultException("corrupt vault file: " + file + " (" + e.getMessage() + ")", e);
        }
        if (!Long.valueOf(VERSION).equals(json.get("version"))) {
            throw new VaultException("unsupported vault version " + json.get("version") + " in " + file);
        }
        byte[] key = decodeKey(json.get("key"), file);
        String createdAt = json.get("createdAt") instanceof String s ? s : "";
        Map<String, String> map = readStringMap(json.get("map"), file);
        Map<String, CollisionEntry> collisions = readCollisions(json.get("collisions"), file);
        return new Vault(file, key, createdAt, map, collisions);
    }

    private static byte[] decodeKey(Object encoded, Path file) {
        if (!(encoded instanceof String s)) {
            throw new VaultException("vault has no key field: " + file);
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new VaultException("vault key is not valid base64: " + file, e);
        }
        if (key.length != KEY_LENGTH_BYTES) {
            throw new VaultException("vault key must be " + KEY_LENGTH_BYTES + " bytes, found "
                    + key.length + ": " + file);
        }
        return key;
    }

    private static Map<String, String> readStringMap(Object value, Path file) {
        if (!(value instanceof Map<?, ?> raw)) {
            throw new VaultException("vault has no token map: " + file);
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (!(entry.getValue() instanceof String original)) {
                throw new VaultException("non-string entry in vault map: " + entry.getKey());
            }
            result.put((String) entry.getKey(), original);
        }
        return result;
    }

    private static Map<String, CollisionEntry> readCollisions(Object value, Path file) {
        if (!(value instanceof Map<?, ?> raw)) {
            throw new VaultException("vault has no collisions section: " + file);
        }
        Map<String, CollisionEntry> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (!(entry.getValue() instanceof Map<?, ?> details)
                    || !(details.get("original") instanceof String original)
                    || !(details.get("extendedToken") instanceof String extendedToken)) {
                throw new VaultException("malformed collision entry in vault: " + entry.getKey());
            }
            result.put((String) entry.getKey(), new CollisionEntry(original, extendedToken));
        }
        return result;
    }

    /** Persists the vault atomically (temp file in the same directory + move). */
    public void save() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", (long) VERSION);
        root.put("createdAt", createdAt);
        root.put("key", Base64.getEncoder().encodeToString(key));
        root.put("map", map);
        Map<String, Object> collisionsJson = new LinkedHashMap<>();
        for (Map.Entry<String, CollisionEntry> entry : collisions.entrySet()) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("original", entry.getValue().original());
            details.put("extendedToken", entry.getValue().extendedToken());
            collisionsJson.put(entry.getKey(), details);
        }
        root.put("collisions", collisionsJson);

        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        try {
            Files.writeString(tmp, MiniJson.write(root), StandardCharsets.UTF_8);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            try {
                Files.deleteIfExists(tmp);
            } catch (IOException ignored) {
                // best effort; the original vault file was never touched
            }
            throw new VaultException("cannot save vault: " + file, e);
        }
        dirty = false;
    }

    /** Saves pending changes. */
    @Override
    public void close() {
        if (dirty) {
            save();
        }
    }

    byte[] key() {
        return key;
    }

    String getOriginal(String token) {
        return map.get(token);
    }

    void put(String token, String original) {
        Objects.requireNonNull(token);
        Objects.requireNonNull(original);
        String existing = map.putIfAbsent(token, original);
        if (existing != null && !existing.equals(original)) {
            throw new VaultException("token " + token + " is already bound to a different original");
        }
        dirty = true;
    }

    void recordCollision(String standardToken, String original, String extendedToken) {
        collisions.put(standardToken, new CollisionEntry(original, extendedToken));
        dirty = true;
    }

    Map<String, CollisionEntry> collisions() {
        return Collections.unmodifiableMap(collisions);
    }

    /** One registered collision: the value that lost the standard form and its extended token. */
    record CollisionEntry(String original, String extendedToken) {
    }
}

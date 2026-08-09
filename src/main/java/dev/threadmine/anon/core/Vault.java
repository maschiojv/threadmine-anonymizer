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
    /** Same contents, with the secret half sealed by a passphrase (SPEC §2). */
    private static final int ENCRYPTED_VERSION = 2;
    private static final int KEY_LENGTH_BYTES = 32;

    private final Path file;
    private final byte[] key;
    private final String createdAt;
    private final Map<String, String> map;
    private final Map<String, CollisionEntry> collisions;
    private final Encryption encryption;
    private boolean dirty;

    private Vault(Path file, byte[] key, String createdAt,
                  Map<String, String> map, Map<String, CollisionEntry> collisions,
                  Encryption encryption) {
        this.file = file;
        this.key = key;
        this.createdAt = createdAt;
        this.map = map;
        this.collisions = collisions;
        this.encryption = encryption;
    }

    /**
     * Derived key plus the KDF parameters needed to re-derive it, held for the
     * lifetime of an encrypted vault so {@link #save()} can re-seal. The
     * passphrase itself is wiped as soon as the key exists.
     */
    private record Encryption(byte[] derivedKey, byte[] salt, int iterations) {

        static Encryption forNewVault(char[] passphrase) {
            byte[] salt = VaultCipher.randomBytes(VaultCipher.SALT_BYTES);
            return new Encryption(
                    VaultCipher.deriveKey(passphrase, salt, VaultCipher.DEFAULT_ITERATIONS),
                    salt, VaultCipher.DEFAULT_ITERATIONS);
        }

        /**
         * Binds the cleartext header to the ciphertext. Without this an
         * attacker could rewrite {@code iterations} down to 1 and hand the file
         * back for the user to open, turning a strong KDF into a weak one.
         */
        String associatedData() {
            return "tm-anon-vault-v" + ENCRYPTED_VERSION
                    + "|" + VaultCipher.KDF_ALGORITHM
                    + "|" + iterations
                    + "|" + Base64.getEncoder().encodeToString(salt)
                    + "|" + VaultCipher.CIPHER_ALGORITHM;
        }
    }

    /** Creates a new plaintext vault with a fresh random 256-bit key and persists it immediately. */
    public static Vault create(Path file) {
        return create(file, null);
    }

    /**
     * Creates a new vault, encrypted at rest when {@code passphrase} is given.
     *
     * @param passphrase the passphrase, or {@code null} for a plaintext vault;
     *                   wiped before this method returns
     */
    public static Vault create(Path file, char[] passphrase) {
        if (Files.exists(file)) {
            throw new VaultException("vault already exists, refusing to overwrite (its key would be lost): " + file);
        }
        if (passphrase != null && passphrase.length == 0) {
            throw new VaultException("passphrase must not be empty - "
                    + "omit it entirely to create a plaintext vault");
        }
        byte[] key = new byte[KEY_LENGTH_BYTES];
        new SecureRandom().nextBytes(key);
        Encryption encryption = null;
        if (passphrase != null) {
            try {
                encryption = Encryption.forNewVault(passphrase);
            } finally {
                VaultCipher.wipe(passphrase);
            }
        }
        Vault vault = new Vault(file, key, Instant.now().toString(),
                new LinkedHashMap<>(), new LinkedHashMap<>(), encryption);
        vault.save();
        return vault;
    }

    /** Loads an existing plaintext vault. */
    public static Vault load(Path file) {
        return load(file, null);
    }

    /**
     * Loads an existing vault.
     *
     * @param passphrase required for an encrypted vault, and rejected for a
     *                   plaintext one — silently ignoring it would leave the
     *                   user believing a plaintext file is protected; wiped
     *                   before this method returns
     */
    public static Vault load(Path file, char[] passphrase) {
        try {
            Map<String, Object> json = parseFile(file);
            Object version = json.get("version");
            if (Long.valueOf(ENCRYPTED_VERSION).equals(version)) {
                if (passphrase == null) {
                    throw new VaultException("vault is encrypted: " + file
                            + " - supply the passphrase (TM_ANON_PASSPHRASE or the interactive prompt)");
                }
                return loadEncrypted(file, json, passphrase);
            }
            if (!Long.valueOf(VERSION).equals(version)) {
                throw new VaultException("unsupported vault version " + version + " in " + file);
            }
            if (passphrase != null) {
                throw new VaultException("vault is not encrypted: " + file
                        + " - a passphrase was supplied but this file has none");
            }
            String createdAt = json.get("createdAt") instanceof String s ? s : "";
            return new Vault(file, decodeKey(json.get("key"), file), createdAt,
                    readStringMap(json.get("map"), file),
                    readCollisions(json.get("collisions"), file), null);
        } finally {
            if (passphrase != null) {
                VaultCipher.wipe(passphrase);
            }
        }
    }

    /** Whether {@code file} is a passphrase-encrypted vault, so callers know to ask for one. */
    public static boolean isEncrypted(Path file) {
        try {
            return Long.valueOf(ENCRYPTED_VERSION).equals(parseFile(file).get("version"));
        } catch (VaultException e) {
            // Unreadable or corrupt: let load() report the real problem.
            return false;
        }
    }

    private static Map<String, Object> parseFile(Path file) {
        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new VaultException("cannot read vault file: " + file, e);
        }
        try {
            return MiniJson.parse(content);
        } catch (MiniJson.ParseException e) {
            throw new VaultException("corrupt vault file: " + file + " (" + e.getMessage() + ")", e);
        }
    }

    private static Vault loadEncrypted(Path file, Map<String, Object> json, char[] passphrase) {
        if (!(json.get("kdf") instanceof Map<?, ?> kdf)) {
            throw new VaultException("encrypted vault has no kdf section: " + file);
        }
        if (!KDF_ALGORITHM_NAME.equals(kdf.get("algorithm"))) {
            throw new VaultException("unsupported vault kdf " + kdf.get("algorithm") + " in " + file);
        }
        if (!(kdf.get("iterations") instanceof Long iterations)) {
            throw new VaultException("encrypted vault has no iteration count: " + file);
        }
        byte[] salt = decodeBase64(kdf.get("salt"), "kdf salt", file);
        byte[] nonce = decodeBase64(json.get("nonce"), "nonce", file);
        if (!(json.get("payload") instanceof String payload)) {
            throw new VaultException("encrypted vault has no payload: " + file);
        }

        Encryption encryption = new Encryption(
                VaultCipher.deriveKey(passphrase, salt, iterations.intValue()),
                salt, iterations.intValue());
        String plaintext = VaultCipher.decrypt(encryption.derivedKey(), nonce,
                encryption.associatedData(), payload);

        Map<String, Object> secret;
        try {
            secret = MiniJson.parse(plaintext);
        } catch (MiniJson.ParseException e) {
            throw new VaultException("corrupt vault payload in " + file + " (" + e.getMessage() + ")", e);
        }
        String createdAt = json.get("createdAt") instanceof String s ? s : "";
        return new Vault(file, decodeKey(secret.get("key"), file), createdAt,
                readStringMap(secret.get("map"), file),
                readCollisions(secret.get("collisions"), file), encryption);
    }

    private static final String KDF_ALGORITHM_NAME = VaultCipher.KDF_ALGORITHM;

    private static byte[] decodeBase64(Object value, String what, Path file) {
        if (!(value instanceof String s)) {
            throw new VaultException("encrypted vault has no " + what + ": " + file);
        }
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new VaultException("vault " + what + " is not valid base64: " + file, e);
        }
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
        Map<String, Object> root = encryption == null ? plaintextRoot() : encryptedRoot();

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

    private Map<String, Object> plaintextRoot() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", (long) VERSION);
        root.put("createdAt", createdAt);
        root.putAll(secretSection());
        return root;
    }

    /**
     * Cleartext header (version, timestamp, KDF parameters, nonce) plus the
     * sealed secret section. A fresh nonce every save is not optional: reusing
     * one under the same GCM key breaks confidentiality outright.
     */
    private Map<String, Object> encryptedRoot() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", (long) ENCRYPTED_VERSION);
        root.put("createdAt", createdAt);
        Map<String, Object> kdf = new LinkedHashMap<>();
        kdf.put("algorithm", VaultCipher.KDF_ALGORITHM);
        kdf.put("iterations", (long) encryption.iterations());
        kdf.put("salt", Base64.getEncoder().encodeToString(encryption.salt()));
        root.put("kdf", kdf);
        root.put("cipher", VaultCipher.CIPHER_ALGORITHM);
        byte[] nonce = VaultCipher.randomBytes(VaultCipher.NONCE_BYTES);
        root.put("nonce", Base64.getEncoder().encodeToString(nonce));
        root.put("payload", VaultCipher.encrypt(encryption.derivedKey(), nonce,
                encryption.associatedData(), MiniJson.write(secretSection())));
        return root;
    }

    /** The half worth protecting: the HMAC key and the token dictionary. */
    private Map<String, Object> secretSection() {
        Map<String, Object> secret = new LinkedHashMap<>();
        secret.put("key", Base64.getEncoder().encodeToString(key));
        secret.put("map", map);
        Map<String, Object> collisionsJson = new LinkedHashMap<>();
        for (Map.Entry<String, CollisionEntry> entry : collisions.entrySet()) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("original", entry.getValue().original());
            details.put("extendedToken", entry.getValue().extendedToken());
            collisionsJson.put(entry.getKey(), details);
        }
        secret.put("collisions", collisionsJson);
        return secret;
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

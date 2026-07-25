package dev.threadmine.anon.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * {@link TokenEngine} backed by HMAC-SHA256 over the vault key (SPEC §1
 * "Derivação"). Keyed derivation means a public algorithm with no dictionary
 * attack: without the vault key a token cannot even be guessed at.
 *
 * <p>Standard token: type code + first 40 bits as 10 lowercase hex with an
 * {@code x} after the 5th. On collision (same standard token, different
 * original) the newcomer takes the extended form: first 56 bits as 14 hex
 * with the {@code x} after the 7th, registered in the vault's collision
 * section. Deterministic from then on.</p>
 */
public final class HmacTokenEngine implements TokenEngine {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int STANDARD_HALF = 5;
    private static final int EXTENDED_HALF = 7;

    /** Digest seam so tests can force 40/56-bit collisions deterministically. */
    interface Digester {
        /** Returns at least 7 bytes of keyed digest for (type, canonicalValue). */
        byte[] digest(byte[] key, TokenType type, String canonicalValue);
    }

    private final Vault vault;
    private final Digester digester;

    public HmacTokenEngine(Vault vault) {
        this(vault, HmacTokenEngine::hmacSha256);
    }

    HmacTokenEngine(Vault vault, Digester digester) {
        this.vault = Objects.requireNonNull(vault);
        this.digester = Objects.requireNonNull(digester);
    }

    @Override
    public String tokenize(TokenType type, String canonicalValue) {
        Objects.requireNonNull(type);
        Objects.requireNonNull(canonicalValue);
        byte[] digest = digester.digest(vault.key(), type, canonicalValue);

        String standard = format(type, digest, STANDARD_HALF);
        String boundToStandard = vault.getOriginal(standard);
        if (boundToStandard == null) {
            vault.put(standard, canonicalValue);
            return standard;
        }
        if (boundToStandard.equals(canonicalValue)) {
            return standard;
        }

        String extended = format(type, digest, EXTENDED_HALF);
        String boundToExtended = vault.getOriginal(extended);
        if (boundToExtended == null) {
            vault.put(extended, canonicalValue);
            vault.recordCollision(standard, canonicalValue, extended);
            return extended;
        }
        if (boundToExtended.equals(canonicalValue)) {
            return extended;
        }
        throw new VaultException("56-bit token collision for type " + type
                + " — cannot assign a distinct token");
    }

    @Override
    public Optional<String> resolve(String token) {
        Objects.requireNonNull(token);
        String bare = token.endsWith("/q") ? token.substring(0, token.length() - 2) : token;
        return Optional.ofNullable(vault.getOriginal(bare));
    }

    /** Type code + first {@code half} bytes as hex with an {@code x} splitting the two halves. */
    private static String format(TokenType type, byte[] digest, int half) {
        String hex = HexFormat.of().formatHex(digest, 0, half);
        return type.code() + hex.substring(0, half) + "x" + hex.substring(half);
    }

    private static byte[] hmacSha256(byte[] key, TokenType type, String canonicalValue) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            byte[] input = (type.code() + ":" + canonicalValue).getBytes(StandardCharsets.UTF_8);
            return mac.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable in this JVM", e);
        }
    }
}

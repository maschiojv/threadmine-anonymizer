package dev.threadmine.anon.core;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Deterministic identifier tokenizer. Same vault key + same canonical value
 * means the same token, in any dump, forever — the property that keeps
 * cross-dump analyses (diff, timeline) working on anonymized input.
 */
public interface TokenEngine {

    /**
     * Single recognition regex for all token forms: standard
     * {@code <type><hex5>x<hex5>}, extended {@code <type><hex7>x<hex7>}, each
     * optionally carrying the {@code /q} route marker. Word boundaries let it
     * find tokens embedded in JSON, CSV or prose.
     */
    Pattern TOKEN_PATTERN =
            Pattern.compile("\\b[pCmt](?:[0-9a-f]{5}x[0-9a-f]{5}|[0-9a-f]{7}x[0-9a-f]{7})(?:/q)?\\b");

    /** Deterministic; registers token-&gt;original in the vault as a side effect. */
    String tokenize(TokenType type, String canonicalValue);

    /** Reverse lookup; empty when unknown to this vault. */
    Optional<String> resolve(String token);

    /** The single recognition regex (standard + extended + {@code /q}). */
    static Pattern tokenPattern() {
        return TOKEN_PATTERN;
    }
}

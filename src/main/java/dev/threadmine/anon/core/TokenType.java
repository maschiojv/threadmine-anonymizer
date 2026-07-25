package dev.threadmine.anon.core;

/**
 * Identifier categories that get tokenized. The single-character code is the
 * first character of every token (SPEC §1) and is part of the HMAC input, so
 * the same value under two types yields unrelated tokens.
 */
public enum TokenType {
    PACKAGE_SEGMENT('p'),
    CLASS_NAME('C'),
    METHOD_NAME('m'),
    THREAD_NAME('t');

    private final char code;

    TokenType(char code) {
        this.code = code;
    }

    public char code() {
        return code;
    }
}

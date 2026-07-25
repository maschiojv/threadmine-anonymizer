package dev.threadmine.anon.core;

/**
 * Raised for any vault problem: missing/corrupt file, wrong version, invalid
 * key material, or an operation that would corrupt the token dictionary.
 * The CLI maps this to exit code 3.
 */
public class VaultException extends RuntimeException {

    public VaultException(String message) {
        super(message);
    }

    public VaultException(String message, Throwable cause) {
        super(message, cause);
    }
}

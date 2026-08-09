package dev.threadmine.anon.core;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Passphrase encryption for the vault at rest (SPEC §2).
 *
 * <p>PBKDF2-HMAC-SHA256 stretches the passphrase into a 256-bit key, and
 * AES-256-GCM encrypts the secret half of the vault. Both come from the JDK:
 * tm-anon ships zero dependencies, so a modern memory-hard KDF (Argon2,
 * scrypt) is not on the table — the iteration count carries the cost instead.
 *
 * <p>The KDF parameters travel in the clear (they have to, to decrypt) but are
 * fed to GCM as associated data, so editing the stored iteration count down to
 * 1 does not produce a file that still opens: authentication fails first.</p>
 */
final class VaultCipher {

    static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    /**
     * OWASP's 2023 floor for PBKDF2-HMAC-SHA256. Costs roughly a quarter of a
     * second per vault open, which is invisible next to masking a dump and
     * expensive enough to matter against an offline guessing attack.
     */
    static final int DEFAULT_ITERATIONS = 600_000;

    static final int SALT_BYTES = 16;
    static final int NONCE_BYTES = 12;
    private static final int KEY_BITS = 256;
    private static final int TAG_BITS = 128;

    private VaultCipher() {
    }

    static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /**
     * Stretches {@code passphrase} into the AES key. The caller keeps the
     * derived key and zeroes the passphrase: a derived key opens this one vault,
     * while the passphrase may well open the user's other things too.
     */
    static byte[] deriveKey(char[] passphrase, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(KDF_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new VaultException("cannot derive the vault key: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }

    static String encrypt(byte[] key, byte[] nonce, String associatedData, String plaintext) {
        try {
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, key, nonce, associatedData);
            return Base64.getEncoder().encodeToString(
                    cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new VaultException("cannot encrypt the vault: " + e.getMessage(), e);
        }
    }

    /**
     * @throws VaultException with a passphrase-shaped message on any
     *         authentication failure — a wrong passphrase, a tampered payload
     *         and edited KDF parameters are indistinguishable here by design,
     *         and the user only ever needs to hear one of them.
     */
    static String decrypt(byte[] key, byte[] nonce, String associatedData, String payload) {
        byte[] ciphertext;
        try {
            ciphertext = Base64.getDecoder().decode(payload);
        } catch (IllegalArgumentException e) {
            throw new VaultException("vault payload is not valid base64", e);
        }
        try {
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, key, nonce, associatedData);
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new VaultException(
                    "wrong passphrase, or the vault file was modified since it was written", e);
        } catch (GeneralSecurityException e) {
            throw new VaultException("cannot decrypt the vault: " + e.getMessage(), e);
        }
    }

    private static Cipher cipher(int mode, byte[] key, byte[] nonce, String associatedData)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
        return cipher;
    }

    /** Best-effort wipe of key material the caller is done with. */
    static void wipe(char[] secret) {
        Arrays.fill(secret, '\0');
    }
}

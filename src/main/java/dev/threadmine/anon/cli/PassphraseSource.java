package dev.threadmine.anon.cli;

import java.io.Console;

/**
 * Where the vault passphrase comes from (SPEC §2 encryption).
 *
 * <p>Two sources, in this order: the {@code TM_ANON_PASSPHRASE} environment
 * variable, for scripts and CI, and an interactive prompt for humans. There is
 * deliberately <b>no</b> {@code --passphrase <value>} flag: a passphrase on the
 * command line lands in shell history and in the process list, where every
 * other user on the machine can read it.</p>
 */
interface PassphraseSource {

    String ENV_VAR = "TM_ANON_PASSPHRASE";

    /** Passphrase for opening an existing vault; {@code null} when none is available. */
    char[] existing();

    /**
     * Whether a passphrase is waiting in the environment, answerable without
     * prompting anyone. {@code init} uses it to refuse creating a PLAINTEXT
     * vault while {@code TM_ANON_PASSPHRASE} is set: that combination is
     * almost always someone who believes they are getting an encrypted vault,
     * and silently handing them an unprotected one is the same failure the
     * loader already refuses in the other direction.
     */
    default boolean presetAvailable() {
        return false;
    }

    /**
     * Passphrase for a vault being created, confirmed by a second entry;
     * {@code null} when none is available or the two entries differ.
     */
    char[] fresh();

    static PassphraseSource standard() {
        return new PassphraseSource() {
            @Override
            public boolean presetAvailable() {
                String value = System.getenv(ENV_VAR);
                return value != null && !value.isEmpty();
            }

            @Override
            public char[] existing() {
                char[] fromEnvironment = fromEnvironment();
                if (fromEnvironment != null) {
                    return fromEnvironment;
                }
                Console console = System.console();
                return console == null ? null : console.readPassword("Vault passphrase: ");
            }

            @Override
            public char[] fresh() {
                char[] fromEnvironment = fromEnvironment();
                if (fromEnvironment != null) {
                    return fromEnvironment;
                }
                Console console = System.console();
                if (console == null) {
                    return null;
                }
                char[] first = console.readPassword("New vault passphrase: ");
                char[] second = console.readPassword("Repeat passphrase: ");
                if (first == null || second == null || !java.util.Arrays.equals(first, second)) {
                    console.printf("Passphrases did not match.%n");
                    return null;
                }
                java.util.Arrays.fill(second, '\0');
                return first;
            }

            private char[] fromEnvironment() {
                String value = System.getenv(ENV_VAR);
                return value == null || value.isEmpty() ? null : value.toCharArray();
            }
        };
    }
}

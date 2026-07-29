package dev.threadmine.anon.cli;

/**
 * Process exit codes fixed by the CLI contract (SPEC §4). Scripts and CI jobs
 * branch on these, so the meanings are frozen: a caller must be able to tell a
 * refused input from a vault problem from a failed compliance check without
 * parsing text.
 */
final class ExitCodes {

    /** Everything worked. */
    static final int OK = 0;

    /**
     * The command line itself was wrong (unknown command/option, missing
     * argument). Not part of SPEC §4, which reserves 0/2/3/4 for outcomes.
     */
    static final int USAGE = 1;

    /**
     * Input refused: unsupported/unrecognized format, or the file could not be
     * read. Fail-closed — tm-anon never guesses its way through an input it
     * does not understand.
     */
    static final int UNSUPPORTED_INPUT = 2;

    /** Vault problem: missing, corrupt, wrong version, or refusing to overwrite. */
    static final int VAULT_ERROR = 3;

    /** {@code verify} ran to completion and the masked file did not pass. */
    static final int VERIFY_FAILED = 4;

    private ExitCodes() {
    }
}

package dev.threadmine.anon.verify;

/**
 * The two allowlist questions {@code verify} needs to ask, with the exact
 * signatures of {@code dev.threadmine.anon.allowlist.AllowlistMatcher}.
 *
 * <p>This is the seam between the verifier and the allowlist module: the
 * verifier decides what counts as a leftover identifier, the allowlist decides
 * what is public infrastructure. Keeping the seam an interface also keeps the
 * strict/lenient tier choice (SPEC §3) out of the verifier, and lets the tests
 * pin allowlist behaviour instead of inheriting whatever the shipped JSON
 * happens to say.</p>
 */
public interface AllowlistLookup {

    /** Longest-prefix match of the allowlisted package prefixes against an FQCN or package. */
    boolean allowsFqcn(String fqcnOrPackage);

    /** Exact / prefix / suffix / regex tiers for thread names. */
    boolean allowsThreadName(String name);
}

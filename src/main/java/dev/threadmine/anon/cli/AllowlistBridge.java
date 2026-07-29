package dev.threadmine.anon.cli;

import dev.threadmine.anon.verify.AllowlistLookup;

/**
 * Single place where the CLI reaches the allowlist module.
 *
 * <p><b>WIRING POINT — replace when task 2E lands.</b> 2E delivers
 * {@code dev.threadmine.anon.allowlist.AllowlistMatcher}, which already has the
 * query methods {@link AllowlistLookup} declares. Once it is on the branch,
 * {@link #fromClasspath()} becomes:</p>
 *
 * <pre>{@code
 * AllowlistMatcher matcher = AllowlistMatcher.fromClasspath().withStrict(strict);
 * return new AllowlistLookup() {
 *     public boolean allowsFqcn(String fqcnOrPackage) { return matcher.allowsFqcn(fqcnOrPackage); }
 *     public boolean allowsThreadName(String name)    { return matcher.allowsThreadName(name); }
 * };
 * }</pre>
 *
 * <p>and {@link #AVAILABLE} flips to {@code true}. Until then the lookup is
 * fail-closed — nothing counts as public infrastructure — which makes
 * {@code verify} loudly useless rather than quietly permissive. An allowlist
 * that silently allowed everything would turn verify into a rubber stamp,
 * which is the one failure mode this tool cannot afford.</p>
 */
final class AllowlistBridge {

    /** False until the allowlist module is part of the build. */
    static final boolean AVAILABLE = false;

    private static final AllowlistLookup FAIL_CLOSED = new AllowlistLookup() {
        @Override
        public boolean allowsFqcn(String fqcnOrPackage) {
            return false;
        }

        @Override
        public boolean allowsThreadName(String name) {
            return false;
        }
    };

    private AllowlistBridge() {
    }

    static AllowlistLookup fromClasspath() {
        return FAIL_CLOSED;
    }
}

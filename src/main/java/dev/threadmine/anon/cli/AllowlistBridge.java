package dev.threadmine.anon.cli;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.verify.AllowlistLookup;

/**
 * Single place where the CLI reaches the allowlist module.
 *
 * <p>Wired to the real {@link AllowlistMatcher} (task 2E): the allowlist ships
 * inside the jar as {@code /allowlist-v1.json}, so {@code verify} judges
 * residual identifiers against the very same rules {@code mask} used.</p>
 */
final class AllowlistBridge {

    /** True: the allowlist module is part of the build. */
    static final boolean AVAILABLE = true;

    private AllowlistBridge() {
    }

    static AllowlistLookup fromClasspath() {
        AllowlistMatcher matcher = AllowlistMatcher.fromClasspath();
        return new AllowlistLookup() {
            @Override
            public boolean allowsFqcn(String fqcnOrPackage) {
                return matcher.allowsFqcn(fqcnOrPackage);
            }

            @Override
            public boolean allowsThreadName(String name) {
                return matcher.allowsThreadName(name);
            }
        };
    }
}

package dev.threadmine.anon.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Stand-in for {@code dev.threadmine.anon.allowlist.AllowlistMatcher} (task
 * 2E), with the same query methods and the same tier semantics as the
 * contract. It is seeded with a representative slice of {@code allowlist-v1.json}
 * so the verifier tests exercise realistic decisions while staying independent
 * of whatever the shipped file happens to contain on any given day.
 */
final class FakeAllowlistMatcher implements AllowlistLookup {

    private final List<String> requiredPackagePrefixes = new ArrayList<>();
    private final List<String> recommendedPackagePrefixes = new ArrayList<>();
    private final List<String> threadNameExact = new ArrayList<>();
    private final List<String> threadNamePrefixes = new ArrayList<>();
    private final List<String> threadNameSuffixes = new ArrayList<>();
    private final List<Pattern> threadNameRegexes = new ArrayList<>();
    private boolean strict;

    private FakeAllowlistMatcher() {
    }

    /** A slice of allowlist-v1.json: enough tiers to prove each one is consulted. */
    static FakeAllowlistMatcher threadMineDefaults() {
        FakeAllowlistMatcher matcher = new FakeAllowlistMatcher();
        matcher.requiredPackagePrefixes.addAll(List.of(
                "java.", "javax.", "jakarta.", "jdk.", "sun.", "com.sun.",
                "org.apache.", "org.springframework.", "io.netty."));
        matcher.recommendedPackagePrefixes.addAll(List.of(
                "com.fasterxml.jackson.", "org.slf4j.", "ch.qos.logback."));
        matcher.threadNameExact.addAll(List.of("DestroyJavaVM", "main"));
        matcher.threadNamePrefixes.addAll(List.of(
                "Reference Handler", "Finalizer", "Attach Listener", "Notification Thread",
                "Monitor Deflation Thread", "Signal Dispatcher", "Common-Cleaner",
                "C1 CompilerThread", "C2 CompilerThread", "GC ", "GC Thread", "G1 ",
                "VM Thread", "VM Periodic Task"));
        matcher.threadNameSuffixes.addAll(List.of("-Acceptor", "-Poller", "-ClientPoller"));
        matcher.threadNameRegexes.addAll(List.of(
                Pattern.compile("^http-nio-\\d+-exec-\\d+$"),
                Pattern.compile("^qtp\\d+-\\d+$"),
                Pattern.compile("^Thread-\\d+$"),
                Pattern.compile("^ForkJoinPool-\\d+-worker-\\d+$"),
                Pattern.compile("^VirtualThread\\[.*")));
        return matcher;
    }

    /** Nothing is public infrastructure: used to prove the verifier really asks. */
    static FakeAllowlistMatcher denyingEverything() {
        return new FakeAllowlistMatcher();
    }

    /** strict=true ignores the "recommended" tier (SPEC §3). */
    FakeAllowlistMatcher withStrict(boolean strict) {
        this.strict = strict;
        return this;
    }

    @Override
    public boolean allowsFqcn(String fqcnOrPackage) {
        for (String prefix : requiredPackagePrefixes) {
            if (fqcnOrPackage.startsWith(prefix)) {
                return true;
            }
        }
        if (strict) {
            return false;
        }
        for (String prefix : recommendedPackagePrefixes) {
            if (fqcnOrPackage.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean allowsThreadName(String name) {
        if (threadNameExact.contains(name)) {
            return true;
        }
        for (String prefix : threadNamePrefixes) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        for (String suffix : threadNameSuffixes) {
            if (name.endsWith(suffix)) {
                return true;
            }
        }
        for (Pattern regex : threadNameRegexes) {
            if (regex.matcher(name).find()) {
                return true;
            }
        }
        return false;
    }
}

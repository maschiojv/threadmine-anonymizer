package dev.threadmine.anon.allowlist;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.regex.Pattern;

/**
 * Decides which identifiers stay verbatim during masking (SPEC §3). The
 * {@code required} tier mirrors everything the ThreadMine detectors, parsers
 * and prompt match by name — tokenizing those names would break detection
 * parity. The {@code recommended} tier lists common public libraries; it is
 * honored by default and ignored under {@code --strict}.
 *
 * <p>Instances are immutable; {@link #withStrict(boolean)} returns a new view
 * over the same data.</p>
 */
public final class AllowlistMatcher {

    private static final String CLASSPATH_RESOURCE = "/allowlist-v1.json";

    private final List<String> requiredPackagePrefixes;
    private final List<String> recommendedPackagePrefixes;
    private final Set<String> threadNameExact;
    private final List<String> threadNamePrefixes;
    private final List<String> threadNameSuffixes;
    private final List<Pattern> threadNameRegexes;
    private final boolean strict;

    private AllowlistMatcher(List<String> requiredPackagePrefixes,
                             List<String> recommendedPackagePrefixes,
                             Set<String> threadNameExact,
                             List<String> threadNamePrefixes,
                             List<String> threadNameSuffixes,
                             List<Pattern> threadNameRegexes,
                             boolean strict) {
        this.requiredPackagePrefixes = requiredPackagePrefixes;
        this.recommendedPackagePrefixes = recommendedPackagePrefixes;
        this.threadNameExact = threadNameExact;
        this.threadNamePrefixes = threadNamePrefixes;
        this.threadNameSuffixes = threadNameSuffixes;
        this.threadNameRegexes = threadNameRegexes;
        this.strict = strict;
    }

    /** Loads allowlist-v1.json from the classpath resource {@value #CLASSPATH_RESOURCE}. */
    public static AllowlistMatcher fromClasspath() {
        try (InputStream in = AllowlistMatcher.class.getResourceAsStream(CLASSPATH_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("allowlist resource missing from jar: " + CLASSPATH_RESOURCE);
            }
            return fromJson(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read allowlist resource: " + CLASSPATH_RESOURCE, e);
        }
    }

    public static AllowlistMatcher fromJson(String json) {
        Map<String, Object> root = AllowlistJson.parse(json);
        Map<String, Object> required = section(root, "required");
        Map<String, Object> recommended = section(root, "recommended");

        List<Pattern> regexes = new ArrayList<>();
        for (String regex : strings(required, "threadNameRegexes")) {
            regexes.add(Pattern.compile(regex));
        }
        return new AllowlistMatcher(
                List.copyOf(strings(required, "packagePrefixes")),
                List.copyOf(strings(recommended, "packagePrefixes")),
                new LinkedHashSet<>(strings(required, "threadNameExact")),
                List.copyOf(strings(required, "threadNamePrefixes")),
                List.copyOf(strings(required, "threadNameSuffixes")),
                List.copyOf(regexes),
                false);
    }

    /** strict=true ignores the "recommended" tier (SPEC §3). */
    public AllowlistMatcher withStrict(boolean strict) {
        if (strict == this.strict) {
            return this;
        }
        return new AllowlistMatcher(requiredPackagePrefixes, recommendedPackagePrefixes,
                threadNameExact, threadNamePrefixes, threadNameSuffixes, threadNameRegexes, strict);
    }

    /** Longest-prefix match of required(+recommended) packagePrefixes against a FQCN or package. */
    public boolean allowsFqcn(String fqcnOrPackage) {
        String longest = null;
        for (String prefix : requiredPackagePrefixes) {
            if (matchesPrefix(fqcnOrPackage, prefix) && (longest == null || prefix.length() > longest.length())) {
                longest = prefix;
            }
        }
        if (!strict) {
            for (String prefix : recommendedPackagePrefixes) {
                if (matchesPrefix(fqcnOrPackage, prefix) && (longest == null || prefix.length() > longest.length())) {
                    longest = prefix;
                }
            }
        }
        return longest != null;
    }

    /**
     * Package prefixes end with a dot; a bare package name equal to the prefix
     * minus the trailing dot also counts (e.g. prefix "java.util." allows the
     * package string "java.util").
     */
    private static boolean matchesPrefix(String fqcnOrPackage, String prefix) {
        return fqcnOrPackage.startsWith(prefix)
                || (prefix.endsWith(".") && fqcnOrPackage.equals(prefix.substring(0, prefix.length() - 1)));
    }

    /** exact OR prefix OR suffix OR regex tiers for thread names. */
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

    private static Map<String, Object> section(Map<String, Object> root, String key) {
        Object value = root.get(key);
        if (value == null) {
            return Map.of();
        }
        if (!(value instanceof Map<?, ?> map)) {
            throw new AllowlistJson.ParseException("allowlist section \"" + key + "\" must be an object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> typed = (Map<String, Object>) map;
        return typed;
    }

    private static List<String> strings(Map<String, Object> section, String key) {
        Object value = section.get(key);
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list)) {
            throw new AllowlistJson.ParseException("allowlist field \"" + key + "\" must be an array");
        }
        List<String> result = new ArrayList<>(list.size());
        for (Object item : list) {
            if (!(item instanceof String s)) {
                throw new AllowlistJson.ParseException("allowlist field \"" + key + "\" must contain only strings");
            }
            result.add(s);
        }
        return result;
    }
}

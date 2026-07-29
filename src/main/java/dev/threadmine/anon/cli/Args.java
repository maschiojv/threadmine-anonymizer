package dev.threadmine.anon.cli;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Minimal command-line option parser: value options ({@code --vault path}),
 * boolean flags ({@code --dry-run}) and positional arguments. Deliberately
 * tiny — tm-anon ships zero runtime dependencies, so there is no argument
 * parsing library to lean on.
 */
final class Args {

    private final List<String> positionals;
    private final Map<String, String> values;
    private final Set<String> flags;

    private Args(List<String> positionals, Map<String, String> values, Set<String> flags) {
        this.positionals = List.copyOf(positionals);
        this.values = Map.copyOf(values);
        this.flags = Set.copyOf(flags);
    }

    /** Raised when the command line cannot be parsed; the CLI maps it to {@link ExitCodes#USAGE}. */
    static final class UsageException extends RuntimeException {
        UsageException(String message) {
            super(message);
        }
    }

    /**
     * Parses {@code argv} (already stripped of the command word).
     *
     * @param valueOptions options that consume the following argument
     * @param flagOptions  options that stand alone
     */
    static Args parse(String[] argv, Set<String> valueOptions, Set<String> flagOptions) {
        List<String> positionals = new ArrayList<>();
        Map<String, String> values = new LinkedHashMap<>();
        Set<String> flags = new java.util.LinkedHashSet<>();

        for (int i = 0; i < argv.length; i++) {
            String arg = argv[i];
            if (!isOption(arg)) {
                positionals.add(arg);
                continue;
            }
            if (flagOptions.contains(arg)) {
                flags.add(arg);
                continue;
            }
            if (valueOptions.contains(arg)) {
                if (i + 1 >= argv.length) {
                    throw new UsageException("option " + arg + " requires a value");
                }
                if (values.put(arg, argv[++i]) != null) {
                    throw new UsageException("option " + arg + " was given more than once");
                }
                continue;
            }
            throw new UsageException("unknown option: " + arg);
        }
        return new Args(positionals, values, flags);
    }

    /** A single {@code -} is a conventional stand-in for stdin, never an option. */
    private static boolean isOption(String arg) {
        return arg.startsWith("-") && arg.length() > 1;
    }

    List<String> positionals() {
        return positionals;
    }

    Optional<String> value(String option) {
        return Optional.ofNullable(values.get(option));
    }

    boolean flag(String option) {
        return flags.contains(option);
    }
}

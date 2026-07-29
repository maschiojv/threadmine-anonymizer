package dev.threadmine.anon.cli;

import java.io.PrintStream;

/**
 * CLI entry point. Command implementations (mask/unmask/verify) live in later
 * milestones; this skeleton only parses the command word and prints usage.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    /** Exit code for usage errors (0/2/3/4 are reserved by the command contract). */
    static final int EXIT_USAGE = 1;

    private static final String USAGE = """
            tm-anon - local, offline anonymizer for JVM thread dumps

            Usage:
              tm-anon init   [--vault <path>]
              tm-anon mask   <dump> [-o <out>] [--vault <path>] [--strict] [--report <path>] [--dry-run]
              tm-anon unmask <file> [-o <out>] [--vault <path>]
              tm-anon verify <original> <masked> [--vault <path>]
            """;

    /** Testable entry point; returns the process exit code instead of exiting. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0) {
            err.println(USAGE);
            return EXIT_USAGE;
        }
        String command = args[0];
        switch (command) {
            case "mask" -> {
                return MaskCommand.run(args, out, err);
            }
            case "init", "unmask", "verify" -> err.println(command + ": not implemented yet");
            default -> {
                err.println("unknown command: " + command);
                err.println(USAGE);
            }
        }
        return EXIT_USAGE;
    }
}

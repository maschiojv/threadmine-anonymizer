package dev.threadmine.anon.cli;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * CLI entry point: parses the command word and delegates. Exit codes are fixed
 * by {@link ExitCodes} (SPEC §4).
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    private static final String USAGE = """
            tm-anon - local, offline anonymizer for JVM thread dumps

            Usage:
              tm-anon init   [--vault <path>]
              tm-anon mask   <dump> [-o <out>] [--vault <path>] [--strict] [--report <path>] [--dry-run]
              tm-anon unmask <file> [-o <out>] [--vault <path>]
              tm-anon verify <original> <masked> [--vault <path>]

            Exit codes: 0 ok - 1 usage - 2 unsupported input - 3 vault error - 4 verify failed
            """;

    /** Testable entry point; returns the process exit code instead of exiting. */
    static int run(String[] args, PrintStream out, PrintStream err) {
        return run(args, Path.of(""), out, err);
    }

    /** Same, with the working directory supplied — relative paths resolve against it. */
    static int run(String[] args, Path workingDir, PrintStream out, PrintStream err) {
        if (args.length == 0) {
            err.println(USAGE);
            return ExitCodes.USAGE;
        }
        String command = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (command) {
            case "init" -> {
                return InitCommand.execute(rest, workingDir, out, err);
            }
            case "mask" -> {
                return MaskCommand.run(args, out, err);
            }
            case "unmask" -> {
                return UnmaskCommand.execute(rest, workingDir, out, err);
            }
            case "verify" -> {
                return VerifyCommand.execute(rest, workingDir, out, err);
            }
            default -> {
                err.println("unknown command: " + command);
                err.println(USAGE);
            }
        }
        return ExitCodes.USAGE;
    }
}

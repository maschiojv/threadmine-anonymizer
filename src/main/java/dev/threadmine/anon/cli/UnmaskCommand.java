package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.core.VaultException;
import dev.threadmine.anon.unmask.UnmaskFormat;
import dev.threadmine.anon.unmask.UnmaskResult;
import dev.threadmine.anon.unmask.Unmasker;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * {@code tm-anon unmask <file> [-o <out>] [--format text|json|html] [--vault <path>]}
 * — puts real names back into anything ThreadMine produced: export JSON, CSV,
 * or a Vein narrative. The file is treated as opaque text, so a format tm-anon
 * has never seen still round-trips.
 *
 * <p>A real name can carry a backslash, a quote or a {@code <}, so how each
 * restored value is escaped depends on where the text is going. The format is
 * inferred from the input file's extension and {@code --format} overrides it,
 * which is what a caller reaching for stdin-like pipelines or an unusual
 * extension needs.</p>
 *
 * <p>Without {@code -o} the result goes to stdout and the summary to stderr,
 * so {@code tm-anon unmask export.json > plain.json} does the obvious thing.</p>
 */
final class UnmaskCommand {

    private static final String OUTPUT_OPTION = "-o";
    private static final String FORMAT_OPTION = "--format";
    private static final int MAX_LISTED_UNRESOLVED = 10;

    private UnmaskCommand() {
    }

    static int execute(String[] argv, Path workingDir, PrintStream out, PrintStream err) {
        Args args;
        try {
            args = Args.parse(argv, Set.of(Commands.VAULT_OPTION, OUTPUT_OPTION, FORMAT_OPTION), Set.of());
        } catch (Args.UsageException e) {
            err.println("unmask: " + e.getMessage());
            return ExitCodes.USAGE;
        }
        if (args.positionals().size() != 1) {
            err.println("unmask: expected exactly one input file");
            err.println("  usage: tm-anon unmask <file> [-o <out>] [--format text|json|html] [--vault <path>]");
            return ExitCodes.USAGE;
        }

        Path input = workingDir.resolve(args.positionals().get(0));
        String text;
        try {
            text = Files.readString(input, StandardCharsets.UTF_8);
        } catch (IOException e) {
            err.println("unmask: cannot read input file: " + input);
            return ExitCodes.UNSUPPORTED_INPUT;
        }

        UnmaskFormat format;
        try {
            format = resolveFormat(args, input);
        } catch (IllegalArgumentException e) {
            err.println("unmask: " + e.getMessage());
            return ExitCodes.USAGE;
        }

        UnmaskResult result;
        Path vaultFile = Commands.vaultPath(args, workingDir);
        try (Vault vault = Commands.openVault(vaultFile)) {
            result = new Unmasker(new HmacTokenEngine(vault)).unmask(text, format);
        } catch (VaultException e) {
            err.println("unmask: " + e.getMessage());
            return ExitCodes.VAULT_ERROR;
        }

        PrintStream summary = err;
        if (args.value(OUTPUT_OPTION).isPresent()) {
            Path output = workingDir.resolve(args.value(OUTPUT_OPTION).get());
            try {
                Files.writeString(output, result.text(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                err.println("unmask: cannot write output file: " + output + " (" + e.getMessage() + ")");
                return ExitCodes.UNSUPPORTED_INPUT;
            }
            out.println("Wrote " + output);
            summary = out;
        } else {
            out.print(result.text());
            out.flush();
        }

        summary.println("Restored " + result.replacedOccurrences() + " token occurrence(s), "
                + result.distinctTokensReplaced() + " distinct.");
        warnAboutUnresolved(result, err);
        return ExitCodes.OK;
    }

    /**
     * The flag wins when given; otherwise the input extension decides. An
     * unrecognised value is a usage error rather than a silent fallback to
     * text: falling back would quietly reintroduce the corruption this option
     * exists to prevent.
     */
    private static UnmaskFormat resolveFormat(Args args, Path input) {
        Optional<String> raw = args.value(FORMAT_OPTION);
        if (raw.isEmpty()) {
            return UnmaskFormat.fromFileName(input.getFileName().toString());
        }
        try {
            return UnmaskFormat.valueOf(raw.get().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "unknown --format '" + raw.get() + "'; expected text, json or html");
        }
    }

    /**
     * Unknown tokens never fail the command — they usually mean the text came
     * from a different vault, which is a fact about the input rather than an
     * error. Naming them is what lets the user find the right vault.
     */
    private static void warnAboutUnresolved(UnmaskResult result, PrintStream err) {
        if (!result.hasUnresolvedTokens()) {
            return;
        }
        List<String> tokens = result.unresolvedTokens();
        err.println("warning: " + result.unresolvedOccurrences() + " occurrence(s) of "
                + tokens.size() + " token(s) are unknown to this vault and were left as they are.");
        err.println("         " + String.join(", ", tokens.subList(0, Math.min(MAX_LISTED_UNRESOLVED, tokens.size())))
                + (tokens.size() > MAX_LISTED_UNRESOLVED ? ", ..." : ""));
        err.println("         Was this text masked with another vault?");
    }
}

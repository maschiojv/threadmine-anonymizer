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
 * {@code tm-anon unmask <file> [-o <out>|-] [--format text|json|html] [--vault <path>]}
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
 * <p>Without {@code -o} the result is written next to the input, the way
 * {@code mask} names its own output: {@code report.html} becomes
 * {@code report.unmasked.html}. Printing it instead was the older behaviour,
 * chosen when the target was a small export a pipeline would swallow; a
 * ThreadMine report is megabytes of HTML, and what it prints is the real
 * names, straight into the terminal scrollback of whoever ran the command the
 * way the product teaches it. {@code -o -} asks for stdout explicitly, and
 * then the summary stays on stderr so the stream is still pipeable.</p>
 */
final class UnmaskCommand {

    private static final String OUTPUT_OPTION = "-o";
    private static final String FORMAT_OPTION = "--format";
    /** {@code -o -}: the one way to ask for the restored text on stdout. */
    private static final String STDOUT = "-";
    private static final String UNMASKED_MARKER = ".unmasked";
    private static final String ANON_MARKER = ".anon";
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
            err.println("  usage: tm-anon unmask <file> [-o <out>|-] [--format text|json|html] [--vault <path>]");
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
        Optional<String> requestedOutput = args.value(OUTPUT_OPTION);
        if (!requestedOutput.map(STDOUT::equals).orElse(false)) {
            Path output = requestedOutput.map(workingDir::resolve).orElseGet(() -> defaultOutput(input));
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
     * {@code report.html -> report.unmasked.html}, and the name mask produced
     * goes back the way it came: {@code dump.anon.txt -> dump.unmasked.txt},
     * extensionless {@code dump -> dump.unmasked}.
     *
     * <p>Never {@code dump.txt}: that is the original, still on disk, and the
     * one file unmask must not touch.</p>
     */
    private static Path defaultOutput(Path input) {
        String name = input.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String stem = dot <= 0 ? name : name.substring(0, dot);
        String extension = dot <= 0 ? "" : name.substring(dot);
        if (stem.endsWith(ANON_MARKER)) {
            stem = stem.substring(0, stem.length() - ANON_MARKER.length());
        }
        String unmaskedName = stem + UNMASKED_MARKER + extension;
        Path parent = input.getParent();
        return parent == null ? Path.of(unmaskedName) : parent.resolve(unmaskedName);
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

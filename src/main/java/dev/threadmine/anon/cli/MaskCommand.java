package dev.threadmine.anon.cli;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.core.VaultException;
import dev.threadmine.anon.format.hotspot.FormatDetector;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.format.hotspot.MaskResult;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code tm-anon mask <dump> [-o <out>] [--vault <path>] [--strict]
 * [--report <path>] [--dry-run]} (SPEC §4). Exit codes: 0 ok, 1 usage,
 * 2 unsupported format (fail-closed), 3 vault error.
 */
final class MaskCommand {

    static final int EXIT_OK = 0;
    static final int EXIT_UNSUPPORTED_FORMAT = 2;
    static final int EXIT_VAULT_ERROR = 3;

    private static final String DEFAULT_VAULT = "tm-anon-vault.json";

    private MaskCommand() {
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        Path input = null;
        Path output = null;
        Path vaultPath = Path.of(DEFAULT_VAULT);
        Path reportPath = null;
        boolean strict = false;
        boolean dryRun = false;

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-o" -> {
                    if (++i >= args.length) {
                        return usage(err, "-o requires a path");
                    }
                    output = Path.of(args[i]);
                }
                case "--vault" -> {
                    if (++i >= args.length) {
                        return usage(err, "--vault requires a path");
                    }
                    vaultPath = Path.of(args[i]);
                }
                case "--report" -> {
                    if (++i >= args.length) {
                        return usage(err, "--report requires a path");
                    }
                    reportPath = Path.of(args[i]);
                }
                case "--strict" -> strict = true;
                case "--dry-run" -> dryRun = true;
                default -> {
                    if (arg.startsWith("-") || input != null) {
                        return usage(err, "unexpected argument: " + arg);
                    }
                    input = Path.of(arg);
                }
            }
        }
        if (input == null) {
            return usage(err, "mask requires a <dump> file");
        }

        String text;
        try {
            text = Files.readString(input, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return usage(err, "cannot read dump file: " + input);
        }

        if (!FormatDetector.isHotspot(text)) {
            err.println("tm-anon: unrecognized dump format (fail-closed refusal, SPEC exit 2).");
            err.println("Only HotSpot-family thread dumps are supported: jstack, jcmd Thread.print,");
            err.println("jcmd Thread.dump_to_file -format=text, ThreadMXBean/VisualVM.");
            return EXIT_UNSUPPORTED_FORMAT;
        }

        // No try-with-resources on purpose: Vault.close() persists a dirty
        // vault, and --dry-run must leave the vault file untouched. Saving is
        // explicit and happens only after the output file was written.
        try {
            Vault vault = Vault.load(vaultPath);
            HotspotRewriter rewriter = new HotspotRewriter(new HmacTokenEngine(vault),
                    AllowlistMatcher.fromClasspath().withStrict(strict));
            MaskResult result = rewriter.mask(text);
            if (dryRun) {
                return finish(result, null, input, reportPath, out, true);
            }
            Path target = output != null ? output : defaultOutput(input);
            try {
                Files.writeString(target, result.output(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                err.println("tm-anon: cannot write output file: " + target);
                return Main.EXIT_USAGE;
            }
            vault.save();
            return finish(result, target, input, reportPath, out, false);
        } catch (VaultException e) {
            err.println("tm-anon: vault error: " + e.getMessage());
            err.println("hint: run `tm-anon init --vault " + vaultPath + "` to create a vault first.");
            return EXIT_VAULT_ERROR;
        } catch (IOException e) {
            err.println("tm-anon: cannot write report: " + e.getMessage());
            return Main.EXIT_USAGE;
        }
    }

    private static int usage(PrintStream err, String message) {
        err.println("tm-anon mask: " + message);
        err.println("usage: tm-anon mask <dump> [-o <out>] [--vault <path>] [--strict] [--report <path>] [--dry-run]");
        return Main.EXIT_USAGE;
    }

    private static int finish(MaskResult result, Path target, Path input, Path reportPath,
                              PrintStream out, boolean dryRun) throws IOException {
        if (dryRun) {
            out.println("dry-run: no output written, vault not updated.");
        } else {
            out.println("masked  " + input + " -> " + target);
        }
        out.println("lines:  " + result.preservedLines() + " preserved, "
                + result.tokenizedLines() + " tokenized, "
                + result.strippedLines() + " stripped, "
                + result.redactedLines() + " redacted");
        for (String warning : result.warnings()) {
            out.println("warning: " + warning);
        }
        out.println("Reminder: upload the masked file under a neutral file name and title -");
        out.println("the original name often carries the very identifiers you just masked.");

        if (reportPath != null) {
            Files.writeString(reportPath, buildReport(result, input), StandardCharsets.UTF_8);
        }
        return EXIT_OK;
    }

    private static String buildReport(MaskResult result, Path input) {
        List<String> lines = new ArrayList<>();
        lines.add("tm-anon mask report");
        lines.add("input: " + input);
        lines.add("lines total: " + result.totalLines());
        lines.add("preserved: " + result.preservedLines());
        lines.add("tokenized: " + result.tokenizedLines());
        lines.add("stripped: " + result.strippedLines());
        lines.add("redacted: " + result.redactedLines());
        lines.add("warnings: " + result.warnings().size());
        for (String warning : result.warnings()) {
            lines.add("  - " + warning);
        }
        return String.join("\n", lines) + "\n";
    }

    /** {@code dump.txt -> dump.anon.txt}; extensionless {@code dump -> dump.anon}. */
    private static Path defaultOutput(Path input) {
        String name = input.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String anonName = dot <= 0
                ? name + ".anon"
                : name.substring(0, dot) + ".anon" + name.substring(dot);
        Path parent = input.getParent();
        return parent == null ? Path.of(anonName) : parent.resolve(anonName);
    }
}

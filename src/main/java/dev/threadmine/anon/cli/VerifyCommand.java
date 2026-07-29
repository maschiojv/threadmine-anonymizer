package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.core.VaultException;
import dev.threadmine.anon.verify.AllowlistLookup;
import dev.threadmine.anon.verify.ComplianceVerifier;
import dev.threadmine.anon.verify.VerifyReport;
import dev.threadmine.anon.verify.VerifyReport.AnchorCheck;
import dev.threadmine.anon.verify.VerifyReport.Finding;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * {@code tm-anon verify <original> <masked> [--vault <path>]} - the compliance
 * gate. It answers the question a security reviewer actually asks: can anything
 * in this file still be traced back to us, and is it still the same dump?
 *
 * <p>Exit 4 when the masked file does not pass; the report says which rule
 * missed and on which line.</p>
 */
final class VerifyCommand {

    private static final int MAX_LISTED_FINDINGS = 20;
    private static final int MAX_LISTED_TOKENS = 10;

    private VerifyCommand() {
    }

    static int execute(String[] argv, Path workingDir, PrintStream out, PrintStream err) {
        return execute(argv, workingDir, out, err, AllowlistBridge.fromClasspath(), AllowlistBridge.AVAILABLE);
    }

    /** Seam for tests: the allowlist is supplied instead of loaded from the classpath. */
    static int execute(String[] argv, Path workingDir, PrintStream out, PrintStream err,
                       AllowlistLookup allowlist, boolean allowlistAvailable) {
        Args args;
        try {
            args = Args.parse(argv, Commands.VAULT_ONLY, Set.of());
        } catch (Args.UsageException e) {
            err.println("verify: " + e.getMessage());
            return ExitCodes.USAGE;
        }
        if (args.positionals().size() != 2) {
            err.println("verify: expected two files, the original dump and the masked one");
            err.println("  usage: tm-anon verify <original> <masked> [--vault <path>]");
            return ExitCodes.USAGE;
        }

        Path originalFile = workingDir.resolve(args.positionals().get(0));
        Path maskedFile = workingDir.resolve(args.positionals().get(1));
        String original = read(originalFile, err);
        String masked = read(maskedFile, err);
        if (original == null || masked == null) {
            return ExitCodes.UNSUPPORTED_INPUT;
        }
        if (!ComplianceVerifier.looksLikeThreadDump(original)) {
            err.println("verify: " + originalFile + " is not a recognizable thread dump - refusing to guess");
            return ExitCodes.UNSUPPORTED_INPUT;
        }

        if (!allowlistAvailable) {
            err.println("verify: warning - the allowlist module is not part of this build, so nothing counts");
            err.println("         as public infrastructure and every non-token identifier is reported.");
        }

        VerifyReport report;
        try (Vault vault = optionalVault(args, workingDir, out)) {
            TokenEngine engine = vault == null ? null : new HmacTokenEngine(vault);
            report = new ComplianceVerifier(allowlist).verify(original, masked, engine);
        } catch (VaultException e) {
            err.println("verify: " + e.getMessage());
            return ExitCodes.VAULT_ERROR;
        }

        print(report, originalFile, maskedFile, out);
        return report.passed() ? ExitCodes.OK : ExitCodes.VERIFY_FAILED;
    }

    private static String read(Path file, PrintStream err) {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            err.println("verify: cannot read " + file);
            return null;
        }
    }

    /**
     * The vault is optional here: it only adds the check that the masked file's
     * tokens belong to the vault kept for it. An explicit {@code --vault} that
     * does not exist is still an error - the user asked for that file.
     */
    private static Vault optionalVault(Args args, Path workingDir, PrintStream out) {
        Path vaultFile = Commands.vaultPath(args, workingDir);
        if (args.value(Commands.VAULT_OPTION).isEmpty() && !Files.exists(vaultFile)) {
            out.println("No vault at " + vaultFile.toAbsolutePath()
                    + "; skipping the token/vault cross-check.");
            return null;
        }
        return Commands.openVault(vaultFile);
    }

    private static void print(VerifyReport report, Path originalFile, Path maskedFile, PrintStream out) {
        out.println("tm-anon verify");
        out.println("  original: " + originalFile);
        out.println("  masked:   " + maskedFile);
        out.println();

        printResidualIdentifiers(report, out);
        printAnchors(report, out);
        printCounts(report, out);
        printNotes(report, out);

        out.println();
        out.println(report.passed()
                ? "PASS - no identifier survived and the structure is intact."
                : "FAIL - this file is not safe to upload.");
    }

    private static void printResidualIdentifiers(VerifyReport report, PrintStream out) {
        List<Finding> findings = report.residualIdentifiers();
        out.println("Residual identifiers (must be 0): " + findings.size());
        for (Finding finding : findings.subList(0, Math.min(MAX_LISTED_FINDINGS, findings.size()))) {
            out.println("  line " + finding.line() + "  " + finding.kind() + "  " + finding.value());
            out.println("    " + finding.lineText());
        }
        if (findings.size() > MAX_LISTED_FINDINGS) {
            out.println("  ... and " + (findings.size() - MAX_LISTED_FINDINGS) + " more");
        }
    }

    private static void printAnchors(VerifyReport report, PrintStream out) {
        List<AnchorCheck> broken = report.brokenAnchors();
        if (broken.isEmpty()) {
            out.println("Structural anchors: " + report.anchors().size() + " checked, all intact");
            return;
        }
        out.println("Structural anchors: " + broken.size() + " of " + report.anchors().size() + " broken");
        for (AnchorCheck anchor : broken) {
            out.println("  \"" + anchor.marker() + "\": " + anchor.inOriginal()
                    + " in original, " + anchor.inMasked() + " in masked");
        }
    }

    private static void printCounts(VerifyReport report, PrintStream out) {
        VerifyReport.Counts counts = report.counts();
        out.println("Counts (original -> masked):");
        out.println("  threads:     " + counts.originalThreads() + " -> " + counts.maskedThreads()
                + mismatch(counts.threadsMatch()));
        out.println("  frames:      " + counts.originalFrames() + " -> " + counts.maskedFrames()
                + mismatch(counts.framesMatch()));
        out.println("  blank lines: " + counts.originalBlankLines() + " -> " + counts.maskedBlankLines()
                + mismatch(counts.blankLinesMatch()));
    }

    private static String mismatch(boolean matches) {
        return matches ? "" : "   <- MISMATCH";
    }

    private static void printNotes(VerifyReport report, PrintStream out) {
        out.println("Tokens in masked file: " + report.counts().tokensInMasked());
        if (report.strippedLines() > 0) {
            out.println("Stripped lines: " + report.strippedLines());
        }
        if (report.redactedLines() > 0) {
            out.println("Redacted lines: " + report.redactedLines()
                    + " (mask could not classify them and removed the content)");
        }
        List<String> unknown = report.unknownTokens();
        if (!unknown.isEmpty()) {
            out.println("Note: " + unknown.size() + " token(s) are unknown to this vault: "
                    + String.join(", ", unknown.subList(0, Math.min(MAX_LISTED_TOKENS, unknown.size())))
                    + (unknown.size() > MAX_LISTED_TOKENS ? ", ..." : ""));
            out.println("      The masked file was probably produced with a different vault.");
        }
    }
}

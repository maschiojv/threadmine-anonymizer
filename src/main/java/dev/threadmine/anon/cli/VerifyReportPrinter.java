package dev.threadmine.anon.cli;

import dev.threadmine.anon.verify.VerifyReport;
import dev.threadmine.anon.verify.VerifyReport.AnchorCheck;
import dev.threadmine.anon.verify.VerifyReport.Finding;

import java.io.PrintStream;
import java.util.List;

/**
 * Renders a {@link VerifyReport}. Both callers share it on purpose: the gate
 * {@code mask} runs on its own output and the standalone {@code verify} command
 * must read identically, or a user comparing the two would think they ran
 * different checks.
 */
final class VerifyReportPrinter {

    private static final int MAX_LISTED_FINDINGS = 20;
    private static final int MAX_LISTED_TOKENS = 10;

    private VerifyReportPrinter() {
    }

    /** The one-line verdict, the last thing printed and the thing people read. */
    static String verdict(VerifyReport report) {
        return report.passed()
                ? "PASS - no identifier survived and the structure is intact."
                : "FAIL - this file is not safe to upload.";
    }

    static void print(VerifyReport report, String originalLabel, String maskedLabel, PrintStream out) {
        out.println("tm-anon verify");
        out.println("  original: " + originalLabel);
        out.println("  masked:   " + maskedLabel);
        out.println();

        printResidualIdentifiers(report, out);
        printAnchors(report, out);
        printCounts(report, out);
        printNotes(report, out);

        out.println();
        out.println(verdict(report));
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

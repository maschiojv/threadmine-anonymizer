package dev.threadmine.anon.verify;

import java.util.List;

/**
 * Compliance report for one original/masked pair (SPEC §4). The masked file
 * passes only when all three questions come back clean: nothing identifiable
 * is left, nothing structural was destroyed, and nothing went missing.
 *
 * @param residualIdentifiers identifiers in the masked file that are neither tokens,
 *                            nor allowlisted, nor structural — must be empty
 * @param anchors             structural markers counted on both sides
 * @param counts              threads, frames and blank lines on both sides
 * @param unknownTokens       tokens in the masked file that the vault cannot reverse
 * @param strippedLines       {@code # [tm-anon: stripped]} markers in the masked file
 * @param redactedLines       {@code # [tm-anon: redacted]} markers — lines mask could not classify
 */
public record VerifyReport(List<Finding> residualIdentifiers,
                           List<AnchorCheck> anchors,
                           Counts counts,
                           List<String> unknownTokens,
                           int strippedLines,
                           int redactedLines) {

    public VerifyReport {
        residualIdentifiers = List.copyOf(residualIdentifiers);
        anchors = List.copyOf(anchors);
        unknownTokens = List.copyOf(unknownTokens);
    }

    /** One identifier that survived masking. */
    public record Finding(int line, Kind kind, String value, String lineText) {

        /** Where the leftover was found, which is what tells mask which rule missed it. */
        public enum Kind {
            FRAME_CLASS,
            SOURCE_FILE,
            THREAD_NAME,
            LOCK_CLASS,
            /** A line of a forbidden javacore section (CI/LK/CL/DC/DG/ST/XE) survived — SPEC §5-B.9. */
            FORBIDDEN_SECTION,
            /** {@code 1TIFILENAME} still carries content — SPEC §5-B.9. */
            FILENAME_CONTENT
        }
    }

    /** A structural marker and how often it appears on each side. */
    public record AnchorCheck(String marker, int inOriginal, int inMasked) {
        public boolean intact() {
            return inOriginal == inMasked;
        }
    }

    /**
     * Volumetrics that must survive masking. Blank lines are in here because
     * they delimit threads in the HotSpot format (SPEC §5.6): creating or
     * removing one silently re-shapes the dump for every parser downstream.
     */
    public record Counts(int originalThreads, int maskedThreads,
                         int originalFrames, int maskedFrames,
                         int originalBlankLines, int maskedBlankLines,
                         int tokensInMasked) {

        public boolean threadsMatch() {
            return originalThreads == maskedThreads;
        }

        public boolean framesMatch() {
            return originalFrames == maskedFrames;
        }

        public boolean blankLinesMatch() {
            return originalBlankLines == maskedBlankLines;
        }

        public boolean allMatch() {
            return threadsMatch() && framesMatch() && blankLinesMatch();
        }
    }

    /** Anchors whose occurrence count changed between the two files. */
    public List<AnchorCheck> brokenAnchors() {
        return anchors.stream().filter(anchor -> !anchor.intact()).toList();
    }

    /**
     * The verdict. Unknown tokens and redacted lines are reported but do not
     * fail the run: the first is a vault mismatch, the second is mask being
     * deliberately fail-closed about a line it did not recognize.
     */
    public boolean passed() {
        return residualIdentifiers.isEmpty() && brokenAnchors().isEmpty() && counts.allMatch();
    }
}

package dev.threadmine.anon.format.hotspot;

import java.util.List;

/**
 * Outcome of masking one HotSpot thread dump. Counters refer to input lines:
 * every input line is either preserved verbatim, tokenized (at least one
 * identifier replaced), stripped (SPEC §5.7) or redacted (fail-closed,
 * SPEC §5.8). Warnings carry one entry per redacted line so the report can
 * point at what the classifier did not recognize.
 */
public record MaskResult(String output,
                         int preservedLines,
                         int tokenizedLines,
                         int strippedLines,
                         int redactedLines,
                         List<String> warnings) {

    public int totalLines() {
        return preservedLines + tokenizedLines + strippedLines + redactedLines;
    }
}

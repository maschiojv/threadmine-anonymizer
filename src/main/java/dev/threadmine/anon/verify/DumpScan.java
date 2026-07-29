package dev.threadmine.anon.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Structural read of a thread dump: how many threads and frames it has, how
 * many blank lines delimit them, and how often each structural marker appears.
 * Both sides of a {@code verify} run are scanned the same way, so the
 * comparison never depends on masking having happened at all.
 *
 * <p>Lines are compared in a whitespace-collapsed form because indentation
 * differs across JDKs and dump flavours ({@code -  waiting on} in
 * ThreadMXBean output vs {@code - waiting on} in jstack), while the markers
 * themselves do not.</p>
 */
final class DumpScan {

    /** Markers that carry meaning for the ThreadMine parsers and detectors (SPEC §5.6). */
    static final List<String> ANCHOR_MARKERS = List.of(
            "Full thread dump",
            "java.lang.Thread.State:",
            "<pinned:",
            "<virtual thread is mounted on carrier thread",
            "Carrying virtual thread #",
            "Java-level deadlock:",
            "Java stack information for the threads listed above:",
            "- locked",
            "- waiting to lock",
            "- waiting on",
            "- parking to wait for",
            "- blocked on");

    /** jcmd {@code Thread.dump_to_file -format=text} header: {@code #12 "name" RUNNABLE}. */
    private static final Pattern JCMD_HEADER = Pattern.compile("^#\\d+\\s+\"([^\"]*)\"");

    /**
     * A frame with no {@code at } keyword, as emitted by jcmd
     * {@code Thread.dump_to_file -format=text}: an unbroken qualified name
     * followed by the location in parentheses. Requiring no whitespace before
     * the parenthesis is what keeps thread headers, lock lines and
     * {@code java.lang.Thread.State: WAITING (parking)} out.
     */
    private static final Pattern BARE_FRAME = Pattern.compile("^[^\\s()]+\\(.*\\)$");

    private static final Pattern LINE_SEPARATOR = Pattern.compile("\r\n|\r|\n");
    private static final Pattern WHITESPACE_RUN = Pattern.compile("\\s+");

    static final String STRIPPED_MARKER = "# [tm-anon: stripped]";
    static final String REDACTED_MARKER = "# [tm-anon: redacted]";

    private final List<String> rawLines;
    private final List<String> collapsedLines;
    private final List<String> threadNames = new ArrayList<>();
    private int frames;
    private int blankLines;
    private int strippedLines;
    private int redactedLines;

    private DumpScan(List<String> rawLines, List<String> collapsedLines) {
        this.rawLines = rawLines;
        this.collapsedLines = collapsedLines;
    }

    static DumpScan of(String text) {
        List<String> raw = new ArrayList<>(List.of(LINE_SEPARATOR.split(text, -1)));
        // A trailing newline is punctuation, not an extra blank line.
        if (!raw.isEmpty() && raw.get(raw.size() - 1).isEmpty()) {
            raw.remove(raw.size() - 1);
        }
        List<String> collapsed = new ArrayList<>(raw.size());
        for (String line : raw) {
            collapsed.add(WHITESPACE_RUN.matcher(line.strip()).replaceAll(" "));
        }
        DumpScan scan = new DumpScan(List.copyOf(raw), List.copyOf(collapsed));
        scan.tally();
        return scan;
    }

    private void tally() {
        for (int i = 0; i < rawLines.size(); i++) {
            String raw = rawLines.get(i);
            String line = collapsedLines.get(i);
            if (raw.isBlank()) {
                blankLines++;
                continue;
            }
            if (line.equals(STRIPPED_MARKER)) {
                strippedLines++;
                continue;
            }
            if (line.equals(REDACTED_MARKER)) {
                redactedLines++;
                continue;
            }
            if (isFrame(line)) {
                frames++;
                continue;
            }
            String name = threadHeaderName(line);
            if (name != null) {
                threadNames.add(name);
            }
        }
    }

    /**
     * The thread name when this line opens a thread, {@code null} otherwise.
     * The quoted names inside a deadlock block ({@code "worker-1":}) are
     * back-references, not new threads.
     */
    static String threadHeaderName(String collapsed) {
        if (collapsed.startsWith("\"")) {
            int closing = collapsed.indexOf('"', 1);
            if (closing < 0) {
                return null;
            }
            String rest = collapsed.substring(closing + 1).strip();
            return rest.equals(":") ? null : collapsed.substring(1, closing);
        }
        Matcher jcmd = JCMD_HEADER.matcher(collapsed);
        return jcmd.find() ? jcmd.group(1) : null;
    }

    static boolean isFrame(String collapsed) {
        return collapsed.startsWith("at ") || BARE_FRAME.matcher(collapsed).matches();
    }

    /** The frame without its {@code at } keyword, ready to be split into name and location. */
    static String frameBody(String collapsed) {
        return collapsed.startsWith("at ") ? collapsed.substring(3).strip() : collapsed;
    }

    /** How many lines carry {@code marker}. */
    int anchorCount(String marker) {
        int count = 0;
        for (String line : collapsedLines) {
            if (line.contains(marker)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Whether this text is a thread dump at all. tm-anon is fail-closed: an
     * input it cannot recognize is refused rather than half-processed.
     */
    boolean looksLikeThreadDump() {
        return !threadNames.isEmpty() || anchorCount("Full thread dump") > 0;
    }

    List<String> rawLines() {
        return rawLines;
    }

    List<String> collapsedLines() {
        return collapsedLines;
    }

    List<String> threadNames() {
        return threadNames;
    }

    int threads() {
        return threadNames.size();
    }

    int frames() {
        return frames;
    }

    int blankLines() {
        return blankLines;
    }

    int strippedLines() {
        return strippedLines;
    }

    int redactedLines() {
        return redactedLines;
    }
}

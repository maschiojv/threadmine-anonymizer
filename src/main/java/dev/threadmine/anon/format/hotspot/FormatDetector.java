package dev.threadmine.anon.format.hotspot;

import java.util.regex.Pattern;

/**
 * Decides whether a text is a HotSpot-family thread dump (SPEC §0 fail-closed:
 * unidentified formats are refused, never silently passed through). The
 * {@code Full thread dump} banner is sufficient but not necessary: partial
 * dumps without it are accepted when thread headers are recognizable, because
 * ThreadMine accepts them too. Only the first 4KB are inspected.
 */
public final class FormatDetector {

    private static final int PROBE_LIMIT = 4096;

    private static final Pattern JSTACK_HEADER =
            Pattern.compile("(?m)^\"[^\"]*\"\\s+.*(#\\d+|prio=\\d|os_prio=\\d|Id=\\d)");
    private static final Pattern JCMD_TEXT_HEADER =
            Pattern.compile("(?m)^#\\d+\\s+\"[^\"]*\"\\s+(VIRTUAL\\s+)?(RUNNABLE|BLOCKED|WAITING|TIMED_WAITING|NEW|TERMINATED)\\b");

    private FormatDetector() {
    }

    public static boolean isHotspot(String text) {
        String probe = text.length() > PROBE_LIMIT ? text.substring(0, PROBE_LIMIT) : text;
        return probe.contains("Full thread dump")
                || probe.contains("java.lang.Thread.State:")
                || JSTACK_HEADER.matcher(probe).find()
                || JCMD_TEXT_HEADER.matcher(probe).find();
    }
}

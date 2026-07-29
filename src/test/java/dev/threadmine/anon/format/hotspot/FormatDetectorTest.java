package dev.threadmine.anon.format.hotspot;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The gate that decides whether tm-anon processes a file at all (SPEC §0
 * fail-closed). Refusing a real dump is as bad as accepting a non-dump: the
 * user simply cannot anonymize the file they were told to anonymize.
 */
class FormatDetectorTest {

    @Test
    void jstackBannerIsEnough() {
        assertTrue(FormatDetector.isHotspot(
                "Full thread dump OpenJDK 64-Bit Server VM (21.0.3+9-LTS mixed mode, sharing):\n"));
    }

    @Test
    void jstackHeaderWithoutBannerIsAccepted() {
        assertTrue(FormatDetector.isHotspot("\"pgto-worker-1\" #24 prio=5 tid=0x1 nid=0x1 runnable\n"));
    }

    /** JDK 24+ {@code Thread.dump_to_file -format=text}. */
    @Test
    void jcmdTextHeaderWithStateAndTimestampIsAccepted() {
        assertTrue(FormatDetector.isHotspot("48350\n2026-07-24T13:02:19.482190Z\n21.0.3+9-LTS\n\n"
                + "#1 \"main\" TIMED_WAITING 2026-07-24T13:02:19.482300Z\n"));
    }

    /**
     * JDK 21..23 {@code Thread.dump_to_file -format=text}: no state on the
     * header line and no {@code java.lang.Thread.State:} line anywhere, so
     * every other detection rule misses it.
     */
    @Test
    void jcmdTextHeaderWithoutStateIsAccepted() {
        assertTrue(FormatDetector.isHotspot("48350\n2026-07-24T13:02:19.482190Z\n21.0.3+9-LTS\n\n"
                + "#1 \"main\"\n      java.base/java.lang.Thread.sleep0(Native Method)\n"));
    }

    @Test
    void jcmdTextVirtualThreadHeaderWithoutStateIsAccepted() {
        assertTrue(FormatDetector.isHotspot("#52 \"\" virtual\n"
                + "      java.base/java.lang.VirtualThread.park(VirtualThread.java:582)\n"));
    }

    @Test
    void unrelatedTextIsRefused() {
        assertFalse(FormatDetector.isHotspot("#1 \"not a dump\" but a list\nhello world\n"));
        assertFalse(FormatDetector.isHotspot("{\"threads\": [{\"name\": \"main\"}]}\n"));
    }
}

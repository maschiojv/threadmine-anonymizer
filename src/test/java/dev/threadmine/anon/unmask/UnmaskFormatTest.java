package dev.threadmine.anon.unmask;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnmaskFormatTest {

    @Test
    void infersJsonAndHtmlFromTheExtension() {
        assertEquals(UnmaskFormat.JSON, UnmaskFormat.fromFileName("export.json"));
        assertEquals(UnmaskFormat.HTML, UnmaskFormat.fromFileName("report.html"));
        assertEquals(UnmaskFormat.HTML, UnmaskFormat.fromFileName("report.htm"));
    }

    @Test
    void isCaseInsensitiveAndIgnoresDirectories() {
        assertEquals(UnmaskFormat.JSON, UnmaskFormat.fromFileName("/tmp/Some Dir/EXPORT.JSON"));
        assertEquals(UnmaskFormat.HTML, UnmaskFormat.fromFileName("C:\\reports\\Report.Html"));
    }

    // Guessing JSON for an unknown extension would silently rewrite plain-text
    // output, so anything we do not recognise keeps the current behaviour.
    @Test
    void fallsBackToTextForAnythingElse() {
        assertEquals(UnmaskFormat.TEXT, UnmaskFormat.fromFileName("dump.txt"));
        assertEquals(UnmaskFormat.TEXT, UnmaskFormat.fromFileName("no-extension"));
        assertEquals(UnmaskFormat.TEXT, UnmaskFormat.fromFileName(""));
        assertEquals(UnmaskFormat.TEXT, UnmaskFormat.fromFileName(null));
        assertEquals(UnmaskFormat.TEXT, UnmaskFormat.fromFileName("archive.json.gz"));
    }

    @Test
    void onlyJsonAndHtmlEscapeAsJsonStrings() {
        assertFalse(UnmaskFormat.TEXT.escapesAsJsonString());
        assertTrue(UnmaskFormat.JSON.escapesAsJsonString());
        assertTrue(UnmaskFormat.HTML.escapesAsJsonString());
    }
}

package dev.threadmine.anon.unmask;

import java.util.Locale;

/**
 * Where the unmasked text is going to live, which decides how each restored
 * value is escaped on its way in.
 *
 * <p>{@link #JSON} and {@link #HTML} behave the same today: in a ThreadMine
 * offline report the data sits in a JSON island inside a {@code <script>}
 * element, so the value is a JSON string fragment either way. They stay
 * separate constants because the CLI infers them from different extensions
 * and because an HTML-only rule would otherwise have nowhere to live.</p>
 */
public enum UnmaskFormat {

    /** Plain text: the value goes in verbatim. This is the historical behaviour. */
    TEXT,

    /** The value sits inside a JSON string. */
    JSON,

    /** The value sits inside a JSON island embedded in HTML. */
    HTML;

    /** Never throws: an extension we do not know keeps the historical behaviour. */
    public static UnmaskFormat fromFileName(String fileName) {
        if (fileName == null) {
            return TEXT;
        }
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".json")) {
            return JSON;
        }
        if (lower.endsWith(".html") || lower.endsWith(".htm")) {
            return HTML;
        }
        return TEXT;
    }

    public boolean escapesAsJsonString() {
        return this != TEXT;
    }
}

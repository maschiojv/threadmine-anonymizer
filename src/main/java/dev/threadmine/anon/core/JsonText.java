package dev.threadmine.anon.core;

/**
 * Escapes a value so it can sit inside a JSON string. Returns a fragment: the
 * caller owns the surrounding quotes.
 *
 * <p>Single source of truth for JSON string escaping in tm-anon. The vault
 * writer, the JSON dump rewriter and the unmasker all go through here, so the
 * next character somebody discovers is a problem only has to be fixed once.</p>
 */
public final class JsonText {

    private JsonText() {
    }

    /**
     * @param escapeAngleBrackets when true, {@code <} becomes {@code \u003c}.
     *        Required only when the JSON is embedded in HTML: the HTML parser
     *        ends a {@code <script>} element at {@code </script>} before any
     *        JSON is read. Off elsewhere so vault and rewriter bytes are stable.
     */
    public static String escape(String value, boolean escapeAngleBrackets) {
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '<' -> {
                    if (escapeAngleBrackets) {
                        sb.append("\\u003c");
                    } else {
                        sb.append(c);
                    }
                }
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}

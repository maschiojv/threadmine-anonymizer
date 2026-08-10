package dev.threadmine.anon.unmask;

import dev.threadmine.anon.core.JsonText;
import dev.threadmine.anon.core.TokenEngine;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Puts real names back into any text that came out of ThreadMine — export
 * JSON, CSV, or Vein prose with tokens embedded in sentences. It knows nothing
 * about thread dump structure: it finds tokens with the single recognition
 * regex (SPEC §1) and replaces them, which is what makes it work on formats
 * nobody has thought of yet.
 *
 * <p>How each restored value is escaped on its way in depends on the
 * {@link UnmaskFormat} the caller asks for: a real name carrying a backslash or
 * a quote is written verbatim in {@code TEXT} and as a JSON string fragment in
 * {@code JSON} and {@code HTML}, so the output stays parseable.</p>
 *
 * <p>Unknown tokens are left exactly as they were and reported. Unmask never
 * fails because of them: a partially reversible report is more useful than an
 * error, and a token from another vault is a fact about the input, not a
 * defect.</p>
 *
 * <p><b>Canonical value vs. rendered value.</b> The vault stores the canonical
 * value used for HMAC derivation (SPEC §1), which is not always what belongs
 * at the token's position: a package-segment token is stored as the whole path
 * up to that segment, a class token as the full FQCN, a method token as
 * {@code FQCN#method}. Substituting those verbatim would rebuild
 * {@code com.acme.Foo.bar} as {@code com.com.acme.com.acme.Foo.com.acme.Foo#bar}.
 * So each token is rendered down to the part that sits at its own position;
 * the surrounding dots and dollars in the masked text put the name back
 * together.</p>
 */
public final class Unmasker {

    private final TokenEngine engine;

    public Unmasker(TokenEngine engine) {
        this.engine = Objects.requireNonNull(engine);
    }

    /** Replaces every recognizable token, treating the text as plain text. */
    public UnmaskResult unmask(String text) {
        return unmask(text, UnmaskFormat.TEXT);
    }

    /**
     * Replaces every recognizable token, escaping each restored value for
     * {@code format}. The input is returned unchanged when there are no tokens.
     */
    public UnmaskResult unmask(String text, UnmaskFormat format) {
        Objects.requireNonNull(text);
        Objects.requireNonNull(format);
        Matcher matcher = TokenEngine.TOKEN_PATTERN.matcher(text);
        StringBuilder rebuilt = new StringBuilder(text.length());
        Set<String> restored = new LinkedHashSet<>();
        Map<String, Integer> unresolved = new LinkedHashMap<>();
        int replacedOccurrences = 0;
        int unresolvedOccurrences = 0;

        while (matcher.find()) {
            String token = matcher.group();
            Optional<String> canonical = engine.resolve(token);
            String replacement;
            if (canonical.isPresent()) {
                replacement = render(token.charAt(0), canonical.get());
                if (format.escapesAsJsonString()) {
                    replacement = JsonText.escape(replacement, true);
                }
                restored.add(token);
                replacedOccurrences++;
            } else {
                replacement = token;
                unresolved.merge(token, 1, Integer::sum);
                unresolvedOccurrences++;
            }
            // quoteReplacement runs LAST: real names carry $ and \, and the
            // JSON escaping above adds more backslashes — all of them are magic
            // in a replacement string and must be neutralised after escaping.
            matcher.appendReplacement(rebuilt, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(rebuilt);

        return new UnmaskResult(rebuilt.toString(), replacedOccurrences, restored.size(),
                unresolved.keySet().stream().toList(), unresolvedOccurrences);
    }

    /** The slice of the canonical value that belongs where this token stands. */
    private static String render(char type, String canonical) {
        return switch (type) {
            case 'p' -> afterLast(canonical, '.');
            case 'C' -> canonical.indexOf('$') >= 0 ? afterLast(canonical, '$') : afterLast(canonical, '.');
            case 'm' -> afterLast(canonical, '#');
            // Thread names are whole values: no path, nothing to trim.
            default -> canonical;
        };
    }

    /**
     * Everything after the last {@code separator}. Falls back to the whole
     * value when the separator is absent or trailing, so a canonical value that
     * does not follow the expected shape still round-trips to something real.
     */
    private static String afterLast(String value, char separator) {
        int at = value.lastIndexOf(separator);
        return at < 0 || at == value.length() - 1 ? value : value.substring(at + 1);
    }
}

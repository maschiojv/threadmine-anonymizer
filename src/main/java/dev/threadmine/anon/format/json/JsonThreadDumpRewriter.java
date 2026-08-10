package dev.threadmine.anon.format.json;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.format.hotspot.MaskResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rewriter for {@code jcmd <pid> Thread.dump_to_file -format=json}.
 *
 * <p>This dialect leaks in a way the text one does not: its
 * {@code threadContainers} carry {@code toString()} of the executor or
 * {@code StructuredTaskScope} that owns each group of threads — for example
 * {@code com.acme.batch.LedgerScope@4f2b1a} — which is the only place in any
 * supported format where an application class names itself outside a stack
 * frame. Lock fields ({@code blockedOn}, {@code waitingOn},
 * {@code parkBlocker}, {@code monitorsOwned}) carry the same shape.</p>
 *
 * <p>Rather than rewrite text line by line, this parses the document, walks it
 * against the schema the JDK dumper emits, and re-serializes. Keys are matched
 * exhaustively: an unknown key has its value replaced by the redaction marker
 * and raises a warning, so a future JDK adding a field cannot leak it through
 * a rewriter that has never heard of it (SPEC §5.8 in structural form).</p>
 *
 * <p><b>Deviation from SPEC §5.9, deliberate:</b> the marker cannot be a
 * leading {@code # tm-anon v1} line without making the document invalid JSON,
 * which is the entire point of this format. The literal marker string is
 * carried as the first key of the root object instead, so it is still found by
 * a substring search. ThreadMine's {@code DetectorDumpAnonimizado} reads the
 * first line only, and its format detector has no JSON
 * pattern at all, so no server behaviour depends on the line form here.</p>
 *
 * <p>The counters in the returned {@link MaskResult} refer to JSON string
 * values, not lines: a dump of this shape has no meaningful line structure.</p>
 */
public final class JsonThreadDumpRewriter {

    public static final String MARKER_KEY = "tmAnon";
    public static final String MARKER_VALUE = "# tm-anon v1";
    private static final String REDACTED = "# [tm-anon: redacted]";

    private static final String ROOT_KEY = "threadDump";
    private static final String CONTAINERS_KEY = "threadContainers";
    private static final String ROOT_CONTAINER = "<root>";

    /** {@code com.acme.Lock@1f2e3d} — SPEC §5.4: class tokenized, identity hash verbatim. */
    private static final Pattern IDENTITY_STRING =
            Pattern.compile("^([A-Za-z_$][\\w.$]*)@([0-9a-fA-F]+)$");
    private static final Pattern DIGITS = Pattern.compile("^\\d+$");

    /** Values the JDK writes for {@code state}; a closed set, so anything else fails closed. */
    private static final Set<String> THREAD_STATES = Set.of(
            "NEW", "RUNNABLE", "BLOCKED", "WAITING", "TIMED_WAITING", "TERMINATED");

    private final HotspotRewriter frames;

    private int preserved;
    private int tokenized;
    private int redacted;
    private final List<String> warnings = new ArrayList<>();

    public JsonThreadDumpRewriter(TokenEngine engine, AllowlistMatcher allowlist) {
        // Delegating to the HotSpot rewriter is what keeps a class token
        // identical across the text, javacore and JSON dialects of one vault.
        this.frames = new HotspotRewriter(Objects.requireNonNull(engine), Objects.requireNonNull(allowlist));
    }

    public MaskResult mask(String text) {
        Object parsed;
        try {
            parsed = Json.parse(text);
        } catch (Json.ParseException e) {
            throw new IllegalArgumentException("not a JSON thread dump: " + e.getMessage(), e);
        }
        if (!(parsed instanceof Map<?, ?> root) || !(root.get(ROOT_KEY) instanceof Map<?, ?> dump)) {
            throw new IllegalArgumentException("not a JSON thread dump: no \"" + ROOT_KEY + "\" object");
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put(MARKER_KEY, MARKER_VALUE);
        output.put(ROOT_KEY, rewriteThreadDump(dump));

        return new MaskResult(Json.write(output), preserved, tokenized, 0, redacted, List.copyOf(warnings));
    }

    private Map<String, Object> rewriteThreadDump(Map<?, ?> dump) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : dump.entrySet()) {
            String key = String.valueOf(entry.getKey());
            Object value = entry.getValue();
            switch (key) {
                // Process id, wall clock and JVM version: the JSON equivalents
                // of the jcmd preamble and the "Full thread dump" banner, both
                // preserved by SPEC §5.6.
                case "processId", "time", "runtimeVersion" -> out.put(key, keep(value));
                case CONTAINERS_KEY -> out.put(key, rewriteContainers(value));
                default -> out.put(key, redact("threadDump." + key));
            }
        }
        return out;
    }

    private Object rewriteContainers(Object value) {
        if (!(value instanceof List<?> containers)) {
            return redact(CONTAINERS_KEY);
        }
        List<Object> out = new ArrayList<>(containers.size());
        for (Object container : containers) {
            out.add(container instanceof Map<?, ?> map
                    ? rewriteContainer(map)
                    : redact("threadContainers[]"));
        }
        return out;
    }

    private Map<String, Object> rewriteContainer(Map<?, ?> container) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : container.entrySet()) {
            String key = String.valueOf(entry.getKey());
            Object value = entry.getValue();
            switch (key) {
                // "container" and "parent" must be rewritten identically:
                // "parent" points at another container by that exact string,
                // and tokens are deterministic, so the link survives masking.
                case "container", "parent" -> out.put(key, rewriteContainerReference(value, key));
                case "owner" -> out.put(key, rewriteThreadReference(value, key));
                case "threadCount" -> out.put(key, keep(value));
                case "threads" -> out.put(key, rewriteThreads(value));
                default -> out.put(key, redact("threadContainers[]." + key));
            }
        }
        return out;
    }

    /**
     * A container is named {@code <root>}, {@code FQCN@hash}, or
     * {@code poolName/FQCN@hash}. The class half follows SPEC §5.4; the pool
     * name half is caller-chosen text ({@code SharedThreadContainer.create})
     * and gets the thread-name cascade, so an application pool name is
     * tokenized rather than published.
     */
    private Object rewriteContainerReference(Object value, String key) {
        if (value == null) {
            return keep(null);
        }
        if (!(value instanceof String text)) {
            return redact("threadContainers[]." + key);
        }
        if (text.equals(ROOT_CONTAINER)) {
            return keep(text);
        }
        int slash = text.lastIndexOf('/');
        String rewrittenClass = rewriteIdentityString(slash < 0 ? text : text.substring(slash + 1));
        if (rewrittenClass == null) {
            return redact("threadContainers[]." + key);
        }
        if (slash < 0) {
            tokenized++;
            return rewrittenClass;
        }
        tokenized++;
        return frames.rewriteThreadName(text.substring(0, slash)) + "/" + rewrittenClass;
    }

    private Object rewriteThreads(Object value) {
        if (!(value instanceof List<?> threads)) {
            return redact("threads");
        }
        List<Object> out = new ArrayList<>(threads.size());
        for (Object thread : threads) {
            out.add(thread instanceof Map<?, ?> map ? rewriteThread(map) : redact("threads[]"));
        }
        return out;
    }

    private Map<String, Object> rewriteThread(Map<?, ?> thread) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : thread.entrySet()) {
            String key = String.valueOf(entry.getKey());
            Object value = entry.getValue();
            switch (key) {
                case "tid", "time", "virtual" -> out.put(key, keep(value));
                case "carrier" -> out.put(key, rewriteThreadReference(value, key));
                case "name" -> out.put(key, rewriteThreadName(value));
                case "state" -> out.put(key, rewriteState(value));
                case "stack" -> out.put(key, rewriteStack(value));
                case "blockedOn", "waitingOn" -> out.put(key, rewriteLockString(value, key));
                case "parkBlocker" -> out.put(key, rewriteParkBlocker(value));
                case "monitorsOwned" -> out.put(key, rewriteMonitorsOwned(value));
                default -> out.put(key, redact("threads[]." + key));
            }
        }
        return out;
    }

    private Object rewriteThreadName(Object value) {
        if (!(value instanceof String name)) {
            return redact("threads[].name");
        }
        if (name.isEmpty()) {
            // An unnamed virtual thread: nothing to mask, and the empty string
            // is meaningful to the reader.
            return keep(name);
        }
        String rewritten = frames.rewriteThreadName(name);
        return classify(name, rewritten);
    }

    private Object rewriteState(Object value) {
        if (value instanceof String state && THREAD_STATES.contains(state)) {
            return keep(state);
        }
        return redact("threads[].state");
    }

    private Object rewriteStack(Object value) {
        if (!(value instanceof List<?> stack)) {
            return redact("threads[].stack");
        }
        List<Object> out = new ArrayList<>(stack.size());
        for (Object element : stack) {
            if (!(element instanceof String frame)) {
                out.add(redact("threads[].stack[]"));
                continue;
            }
            String rewritten = frames.rewriteFrameBody(frame);
            if (rewritten == null) {
                out.add(redact("threads[].stack[]: " + frame));
                continue;
            }
            out.add(classify(frame, rewritten));
        }
        return out;
    }

    private Object rewriteLockString(Object value, String key) {
        if (value == null) {
            return keep(null);
        }
        if (!(value instanceof String text)) {
            return redact("threads[]." + key);
        }
        String rewritten = rewriteIdentityString(text);
        return rewritten == null ? redact("threads[]." + key) : classify(text, rewritten);
    }

    /** {@code "parkBlocker": {"object": "…", "exclusiveOwnerThread": {…}}}. */
    private Object rewriteParkBlocker(Object value) {
        if (!(value instanceof Map<?, ?> blocker)) {
            return redact("threads[].parkBlocker");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : blocker.entrySet()) {
            String key = String.valueOf(entry.getKey());
            Object nested = entry.getValue();
            switch (key) {
                case "object" -> out.put(key, rewriteLockString(nested, "parkBlocker.object"));
                case "exclusiveOwnerThread" -> out.put(key, nested instanceof Map<?, ?> owner
                        ? rewriteThread(owner)
                        : redact("threads[].parkBlocker.exclusiveOwnerThread"));
                default -> out.put(key, redact("threads[].parkBlocker." + key));
            }
        }
        return out;
    }

    /** {@code "monitorsOwned": [{"depth": 4, "locks": ["…"]}]}. */
    private Object rewriteMonitorsOwned(Object value) {
        if (!(value instanceof List<?> monitors)) {
            return redact("threads[].monitorsOwned");
        }
        List<Object> out = new ArrayList<>(monitors.size());
        for (Object monitor : monitors) {
            if (!(monitor instanceof Map<?, ?> map)) {
                out.add(redact("threads[].monitorsOwned[]"));
                continue;
            }
            Map<String, Object> entryOut = new LinkedHashMap<>();
            for (Map.Entry<?, ?> field : map.entrySet()) {
                String key = String.valueOf(field.getKey());
                Object nested = field.getValue();
                switch (key) {
                    case "depth" -> entryOut.put(key, keep(nested));
                    case "locks" -> entryOut.put(key, rewriteLocks(nested));
                    default -> entryOut.put(key, redact("threads[].monitorsOwned[]." + key));
                }
            }
            out.add(entryOut);
        }
        return out;
    }

    private Object rewriteLocks(Object value) {
        if (!(value instanceof List<?> locks)) {
            return redact("threads[].monitorsOwned[].locks");
        }
        List<Object> out = new ArrayList<>(locks.size());
        for (Object lock : locks) {
            out.add(rewriteLockString(lock, "monitorsOwned[].locks[]"));
        }
        return out;
    }

    /** A reference to another thread by tid; digits only, so it carries no name. */
    private Object rewriteThreadReference(Object value, String key) {
        if (value == null) {
            return keep(null);
        }
        if (value instanceof String text && DIGITS.matcher(text).matches()) {
            return keep(text);
        }
        if (value instanceof Long) {
            return keep(value);
        }
        return redact("threadContainers[]." + key);
    }

    /** {@code FQCN@hash} to {@code <class token>@hash}, or {@code null} when it is neither. */
    private String rewriteIdentityString(String text) {
        Matcher identity = IDENTITY_STRING.matcher(text);
        if (!identity.matches()) {
            return null;
        }
        return frames.rewriteClassReference(identity.group(1)) + "@" + identity.group(2);
    }

    private Object keep(Object value) {
        preserved++;
        return value;
    }

    private String classify(String original, String rewritten) {
        if (original.equals(rewritten)) {
            preserved++;
        } else {
            tokenized++;
        }
        return rewritten;
    }

    private String redact(String path) {
        redacted++;
        warnings.add(path + " not recognized, redacted (fail-closed)");
        return REDACTED;
    }
}

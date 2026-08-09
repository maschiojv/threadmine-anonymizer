package dev.threadmine.anon.verify;

import dev.threadmine.anon.format.json.Json;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Structural read of a {@code -format=json} thread dump, the JSON counterpart
 * of {@link DumpScan}.
 *
 * <p>A line-oriented scan cannot audit this dialect: every JSON key and value
 * is a quoted string, so the "quoted text is a thread name" rule would flag
 * {@code "threadDump"} and miss a class name buried in {@code parkBlocker}.
 * This walks the document instead and hands the verifier a flat list of the
 * values that are allowed to carry an identifier, each tagged with where it
 * came from, so a finding can point at {@code threads[3].blockedOn} rather
 * than a line number that means nothing in a re-serialized file.</p>
 */
final class JsonDumpScan {

    /**
     * Keys that must survive masking. They are the JSON equivalent of the
     * structural anchors of SPEC §5.6: losing one means the rewriter dropped a
     * part of the dump rather than masking it.
     */
    static final List<String> ANCHOR_KEYS = List.of(
            "\"threadDump\"", "\"threadContainers\"", "\"container\"", "\"threads\"",
            "\"stack\"", "\"blockedOn\"", "\"waitingOn\"", "\"parkBlocker\"", "\"monitorsOwned\"");

    private static final String REDACTED = "# [tm-anon: redacted]";

    /** One value that is allowed to carry an identifier, and therefore must be masked. */
    record Candidate(String path, Kind kind, String value) {
        enum Kind { THREAD_NAME, FRAME, LOCK, CONTAINER_CLASS, CONTAINER_POOL }
    }

    private final boolean valid;
    private final List<Candidate> candidates = new ArrayList<>();
    private int threads;
    private int frames;
    private int redactedValues;

    private JsonDumpScan(boolean valid) {
        this.valid = valid;
    }

    static JsonDumpScan of(String text) {
        Object parsed;
        try {
            parsed = Json.parse(text);
        } catch (RuntimeException e) {
            // Not JSON, or not shaped like anything we can walk: the caller
            // falls back to the line-oriented scan.
            return new JsonDumpScan(false);
        }
        if (!(parsed instanceof Map<?, ?> root) || !(root.get("threadDump") instanceof Map<?, ?> dump)) {
            return new JsonDumpScan(false);
        }
        JsonDumpScan scan = new JsonDumpScan(true);
        scan.walkContainers(dump.get("threadContainers"));
        return scan;
    }

    private void walkContainers(Object value) {
        if (!(value instanceof List<?> containers)) {
            return;
        }
        for (int i = 0; i < containers.size(); i++) {
            if (containers.get(i) instanceof Map<?, ?> container) {
                walkContainer(container, "threadContainers[" + i + "]");
            }
        }
    }

    private void walkContainer(Map<?, ?> container, String path) {
        for (String key : List.of("container", "parent")) {
            if (container.get(key) instanceof String reference && !reference.equals("<root>")) {
                addContainerReference(reference, path + "." + key);
            }
        }
        if (container.get("threads") instanceof List<?> threadList) {
            for (int i = 0; i < threadList.size(); i++) {
                if (threadList.get(i) instanceof Map<?, ?> thread) {
                    threads++;
                    walkThread(thread, path + ".threads[" + i + "]");
                }
            }
        }
    }

    /** {@code poolName/FQCN@hash} or {@code FQCN@hash}: two independently maskable halves. */
    private void addContainerReference(String reference, String path) {
        if (count(reference)) {
            return;
        }
        int slash = reference.lastIndexOf('/');
        if (slash >= 0) {
            candidates.add(new Candidate(path, Candidate.Kind.CONTAINER_POOL, reference.substring(0, slash)));
        }
        candidates.add(new Candidate(path, Candidate.Kind.CONTAINER_CLASS,
                slash < 0 ? reference : reference.substring(slash + 1)));
    }

    private void walkThread(Map<?, ?> thread, String path) {
        if (thread.get("name") instanceof String name && !name.isEmpty() && !count(name)) {
            candidates.add(new Candidate(path + ".name", Candidate.Kind.THREAD_NAME, name));
        }
        if (thread.get("stack") instanceof List<?> stack) {
            for (int i = 0; i < stack.size(); i++) {
                if (stack.get(i) instanceof String frame) {
                    frames++;
                    if (!count(frame)) {
                        candidates.add(new Candidate(path + ".stack[" + i + "]",
                                Candidate.Kind.FRAME, frame));
                    }
                }
            }
        }
        for (String key : List.of("blockedOn", "waitingOn")) {
            if (thread.get(key) instanceof String lock && !count(lock)) {
                candidates.add(new Candidate(path + "." + key, Candidate.Kind.LOCK, lock));
            }
        }
        if (thread.get("parkBlocker") instanceof Map<?, ?> blocker) {
            if (blocker.get("object") instanceof String lock && !count(lock)) {
                candidates.add(new Candidate(path + ".parkBlocker.object", Candidate.Kind.LOCK, lock));
            }
            if (blocker.get("exclusiveOwnerThread") instanceof Map<?, ?> owner) {
                walkThread(owner, path + ".parkBlocker.exclusiveOwnerThread");
            }
        }
        if (thread.get("monitorsOwned") instanceof List<?> monitors) {
            for (int i = 0; i < monitors.size(); i++) {
                if (monitors.get(i) instanceof Map<?, ?> monitor
                        && monitor.get("locks") instanceof List<?> locks) {
                    for (int j = 0; j < locks.size(); j++) {
                        if (locks.get(j) instanceof String lock && !count(lock)) {
                            candidates.add(new Candidate(
                                    path + ".monitorsOwned[" + i + "].locks[" + j + "]",
                                    Candidate.Kind.LOCK, lock));
                        }
                    }
                }
            }
        }
    }

    /** Tallies a redaction marker; {@code true} means the value needs no further checking. */
    private boolean count(String value) {
        if (value.equals(REDACTED)) {
            redactedValues++;
            return true;
        }
        return false;
    }

    boolean valid() {
        return valid;
    }

    List<Candidate> candidates() {
        return List.copyOf(candidates);
    }

    int threads() {
        return threads;
    }

    int frames() {
        return frames;
    }

    int redactedValues() {
        return redactedValues;
    }
}

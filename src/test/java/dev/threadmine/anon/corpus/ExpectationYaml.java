package dev.threadmine.anon.corpus;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Minimal reader for the corpus expectation schema (SPEC §6). Test-scope only:
 * the shipped jar gains no YAML dependency and the no-network architecture
 * test stays authoritative. Supports exactly what the corpus uses — top-level
 * scalars, lists of scalars, one level of inline maps, quoted strings with
 * {@code \"} escapes, full-line and trailing comments.
 */
final class ExpectationYaml {

    String format = "";
    boolean nativeIdsVerbatim = false;
    final List<String> preservedAnchors = new ArrayList<>();
    final List<String> allowlistedThreadsVerbatim = new ArrayList<>();
    final Map<String, Tokenized> tokenizedThreads = new LinkedHashMap<>();
    final List<String> tokenizedClasses = new ArrayList<>();
    final List<String> strippedLines = new ArrayList<>();
    final Set<String> invariants = new LinkedHashSet<>();
    // javacore extensions (SPEC §5-B / §6)
    final List<String> detectionAnchors4kb = new ArrayList<>();
    final List<String> preservedSections = new ArrayList<>();
    final List<String> strippedSections = new ArrayList<>();
    final List<String> redactedLines = new ArrayList<>();

    boolean isJavacore() {
        return format.startsWith("openj9");
    }

    boolean isJson() {
        return format.startsWith("hotspot-json");
    }

    record Tokenized(String keepsSuffix, boolean routeMarker) {
    }

    static ExpectationYaml parse(String yaml) {
        ExpectationYaml result = new ExpectationYaml();
        String section = null;
        for (String rawLine : yaml.split("\n", -1)) {
            String line = stripComment(rawLine).stripTrailing();
            if (line.isBlank()) {
                continue;
            }
            if (!rawLine.startsWith(" ")) {
                int colon = line.indexOf(':');
                if (colon < 0) {
                    throw new IllegalArgumentException("unparseable top-level line: " + rawLine);
                }
                String key = line.substring(0, colon).trim();
                String rest = line.substring(colon + 1).trim();
                if (key.equals("format")) {
                    result.format = rest;
                    section = null;
                } else if (key.equals("native_ids_verbatim")) {
                    result.nativeIdsVerbatim = Boolean.parseBoolean(rest);
                    section = null;
                } else {
                    section = key;
                    if (!rest.isEmpty() && !rest.equals("[]")) {
                        throw new IllegalArgumentException("unsupported inline value for " + key + ": " + rest);
                    }
                }
                continue;
            }
            String item = line.strip();
            if (item.startsWith("- ")) {
                result.addListItem(section, parseScalar(item.substring(2).strip()));
            } else {
                result.addMapItem(section, item);
            }
        }
        return result;
    }

    private void addListItem(String section, String value) {
        switch (section) {
            case "preserved_anchors" -> preservedAnchors.add(value);
            case "allowlisted_threads_verbatim" -> allowlistedThreadsVerbatim.add(value);
            case "tokenized_classes" -> tokenizedClasses.add(value);
            case "stripped_lines" -> strippedLines.add(value);
            case "invariants" -> invariants.add(value);
            case "detection_anchors_4kb" -> detectionAnchors4kb.add(value);
            case "preserved_sections" -> preservedSections.add(value);
            case "stripped_sections" -> strippedSections.add(value);
            case "redacted_lines" -> redactedLines.add(value);
            default -> throw new IllegalArgumentException("list item outside a known section: " + section);
        }
    }

    private void addMapItem(String section, String item) {
        if (!"tokenized_threads".equals(section)) {
            throw new IllegalArgumentException("map entry outside tokenized_threads: " + item);
        }
        if (!item.startsWith("\"")) {
            throw new IllegalArgumentException("thread name key must be quoted: " + item);
        }
        int endQuote = findClosingQuote(item, 0);
        String name = unescape(item.substring(1, endQuote));
        String rest = item.substring(endQuote + 1).strip();
        if (!rest.startsWith(":")) {
            throw new IllegalArgumentException("expected ':' after thread name: " + item);
        }
        String inline = rest.substring(1).strip();
        if (!inline.startsWith("{") || !inline.endsWith("}")) {
            throw new IllegalArgumentException("expected inline map for thread " + name + ": " + inline);
        }
        String body = inline.substring(1, inline.length() - 1).strip();
        String keepsSuffix = null;
        boolean routeMarker = false;
        if (!body.isEmpty()) {
            for (String pair : body.split(",")) {
                int colon = pair.indexOf(':');
                String key = pair.substring(0, colon).strip();
                String value = parseScalar(pair.substring(colon + 1).strip());
                switch (key) {
                    case "keeps_suffix" -> keepsSuffix = value;
                    case "route_marker" -> routeMarker = Boolean.parseBoolean(value);
                    default -> throw new IllegalArgumentException("unknown tokenized attribute: " + key);
                }
            }
        }
        tokenizedThreads.put(name, new Tokenized(keepsSuffix, routeMarker));
    }

    private static String parseScalar(String text) {
        if (text.startsWith("\"")) {
            int end = findClosingQuote(text, 0);
            return unescape(text.substring(1, end));
        }
        return text;
    }

    private static int findClosingQuote(String text, int openIndex) {
        for (int i = openIndex + 1; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == '"') {
                return i;
            }
        }
        throw new IllegalArgumentException("unterminated quoted string: " + text);
    }

    private static String unescape(String text) {
        return text.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    /** Cuts a {@code #} comment, ignoring {@code #} inside quoted strings. */
    private static String stripComment(String line) {
        boolean inQuote = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\\' && inQuote) {
                i++;
            } else if (c == '"') {
                inQuote = !inQuote;
            } else if (c == '#' && !inQuote) {
                return line.substring(0, i);
            }
        }
        return line;
    }
}

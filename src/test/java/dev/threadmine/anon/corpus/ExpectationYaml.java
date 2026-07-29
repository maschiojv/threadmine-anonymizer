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

    String formato = "";
    boolean idsNativosVerbatim = false;
    final List<String> ancorasPreservadas = new ArrayList<>();
    final List<String> threadsAllowlistVerbatim = new ArrayList<>();
    final Map<String, Tokenized> threadsTokenizadas = new LinkedHashMap<>();
    final List<String> classesTokenizadas = new ArrayList<>();
    final List<String> linhasStripadas = new ArrayList<>();
    final Set<String> invariantes = new LinkedHashSet<>();
    // javacore extensions (SPEC §5-B / §6)
    final List<String> ancorasDeteccao4kb = new ArrayList<>();
    final List<String> secoesPreservadas = new ArrayList<>();
    final List<String> secoesStripadas = new ArrayList<>();
    final List<String> linhasRedigidas = new ArrayList<>();

    boolean isJavacore() {
        return formato.startsWith("openj9");
    }

    record Tokenized(String preservaSufixo, boolean marcadorRota) {
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
                if (key.equals("formato")) {
                    result.formato = rest;
                    section = null;
                } else if (key.equals("ids_nativos_verbatim")) {
                    result.idsNativosVerbatim = Boolean.parseBoolean(rest);
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
            case "ancoras_preservadas" -> ancorasPreservadas.add(value);
            case "threads_allowlist_verbatim" -> threadsAllowlistVerbatim.add(value);
            case "classes_tokenizadas" -> classesTokenizadas.add(value);
            case "linhas_stripadas" -> linhasStripadas.add(value);
            case "invariantes" -> invariantes.add(value);
            case "ancoras_deteccao_4kb" -> ancorasDeteccao4kb.add(value);
            case "secoes_preservadas" -> secoesPreservadas.add(value);
            case "secoes_stripadas" -> secoesStripadas.add(value);
            case "linhas_redigidas" -> linhasRedigidas.add(value);
            default -> throw new IllegalArgumentException("list item outside a known section: " + section);
        }
    }

    private void addMapItem(String section, String item) {
        if (!"threads_tokenizadas".equals(section)) {
            throw new IllegalArgumentException("map entry outside threads_tokenizadas: " + item);
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
        String preservaSufixo = null;
        boolean marcadorRota = false;
        if (!body.isEmpty()) {
            for (String pair : body.split(",")) {
                int colon = pair.indexOf(':');
                String key = pair.substring(0, colon).strip();
                String value = parseScalar(pair.substring(colon + 1).strip());
                switch (key) {
                    case "preserva_sufixo" -> preservaSufixo = value;
                    case "marcador_rota" -> marcadorRota = Boolean.parseBoolean(value);
                    default -> throw new IllegalArgumentException("unknown tokenized attribute: " + key);
                }
            }
        }
        threadsTokenizadas.put(name, new Tokenized(preservaSufixo, marcadorRota));
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

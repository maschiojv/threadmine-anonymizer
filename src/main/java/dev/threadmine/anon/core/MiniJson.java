package dev.threadmine.anon.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal JSON reader/writer for the vault file, restricted on purpose to the
 * vault schema: objects, strings and integers. tm-anon ships with zero runtime
 * dependencies as an auditability guarantee, so the vault cannot pull in a
 * JSON library. Anything outside the schema (arrays, floats, booleans, null,
 * duplicate keys) is treated as corruption and rejected.
 */
final class MiniJson {

    private MiniJson() {
    }

    static String write(Map<String, ?> root) {
        StringBuilder sb = new StringBuilder();
        writeObject(sb, root, 0);
        sb.append('\n');
        return sb.toString();
    }

    private static void writeObject(StringBuilder sb, Map<String, ?> object, int indent) {
        if (object.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        int i = 0;
        for (Map.Entry<String, ?> entry : object.entrySet()) {
            sb.append("  ".repeat(indent + 1));
            writeString(sb, entry.getKey());
            sb.append(": ");
            writeValue(sb, entry.getValue(), indent + 1);
            if (++i < object.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append("  ".repeat(indent)).append('}');
    }

    private static void writeValue(StringBuilder sb, Object value, int indent) {
        switch (value) {
            case String s -> writeString(sb, s);
            case Integer n -> sb.append((long) n);
            case Long n -> sb.append((long) n);
            case Map<?, ?> m -> {
                @SuppressWarnings("unchecked")
                Map<String, ?> nested = (Map<String, ?>) m;
                writeObject(sb, nested, indent);
            }
            default -> throw new IllegalArgumentException(
                    "unsupported value type for vault JSON: " + (value == null ? "null" : value.getClass().getName()));
        }
    }

    private static void writeString(StringBuilder sb, String value) {
        sb.append('"');
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
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    static Map<String, Object> parse(String json) {
        Parser parser = new Parser(json);
        parser.skipWhitespace();
        Map<String, Object> root = parser.parseObject();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw parser.error("trailing content after JSON document");
        }
        return root;
    }

    /** Thrown when the input is not valid JSON or falls outside the vault schema. */
    static final class ParseException extends RuntimeException {
        ParseException(String message) {
            super(message);
        }
    }

    private static final class Parser {
        private final String input;
        private int pos;

        Parser(String input) {
            this.input = input;
        }

        Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> object = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return object;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                Object value = parseValue();
                if (object.putIfAbsent(key, value) != null) {
                    throw error("duplicate key: \"" + key + "\"");
                }
                skipWhitespace();
                char c = next();
                if (c == '}') {
                    return object;
                }
                if (c != ',') {
                    throw errorAt(pos - 1, "expected ',' or '}' but found '" + c + "'");
                }
            }
        }

        private Object parseValue() {
            char c = peek();
            if (c == '"') {
                return parseString();
            }
            if (c == '{') {
                return parseObject();
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return parseInteger();
            }
            throw error("unexpected character '" + c + "' (vault schema allows only objects, strings and integers)");
        }

        private Long parseInteger() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            while (!atEnd() && Character.isDigit(input.charAt(pos))) {
                pos++;
            }
            String literal = input.substring(start, pos);
            if (literal.isEmpty() || literal.equals("-")) {
                throw errorAt(start, "invalid number");
            }
            if (!atEnd() && (input.charAt(pos) == '.' || input.charAt(pos) == 'e' || input.charAt(pos) == 'E')) {
                throw errorAt(pos, "non-integer numbers are outside the vault schema");
            }
            try {
                return Long.parseLong(literal);
            } catch (NumberFormatException e) {
                throw errorAt(start, "integer out of range: " + literal);
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw error("unterminated string");
                }
                char c = input.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    sb.append(parseEscape());
                } else {
                    sb.append(c);
                }
            }
        }

        private char parseEscape() {
            if (atEnd()) {
                throw error("unterminated escape sequence");
            }
            char c = input.charAt(pos++);
            return switch (c) {
                case '"' -> '"';
                case '\\' -> '\\';
                case '/' -> '/';
                case 'n' -> '\n';
                case 'r' -> '\r';
                case 't' -> '\t';
                case 'b' -> '\b';
                case 'f' -> '\f';
                case 'u' -> parseUnicodeEscape();
                default -> throw errorAt(pos - 1, "invalid escape '\\" + c + "'");
            };
        }

        private char parseUnicodeEscape() {
            if (pos + 4 > input.length()) {
                throw error("truncated \\u escape");
            }
            String hex = input.substring(pos, pos + 4);
            try {
                char value = (char) Integer.parseInt(hex, 16);
                pos += 4;
                return value;
            } catch (NumberFormatException e) {
                throw error("invalid \\u escape: " + hex);
            }
        }

        void skipWhitespace() {
            while (!atEnd()) {
                char c = input.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    return;
                }
            }
        }

        boolean atEnd() {
            return pos >= input.length();
        }

        private char peek() {
            if (atEnd()) {
                throw error("unexpected end of input");
            }
            return input.charAt(pos);
        }

        private char next() {
            if (atEnd()) {
                throw error("unexpected end of input");
            }
            return input.charAt(pos++);
        }

        private void expect(char expected) {
            char c = next();
            if (c != expected) {
                throw errorAt(pos - 1, "expected '" + expected + "' but found '" + c + "'");
            }
        }

        ParseException error(String message) {
            return errorAt(pos, message);
        }

        ParseException errorAt(int offset, String message) {
            return new ParseException("JSON error at offset " + offset + ": " + message);
        }
    }
}

package dev.threadmine.anon.allowlist;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader for the allowlist artifact. The core vault reader
 * ({@code MiniJson}) deliberately rejects arrays as vault corruption, so the
 * allowlist — whose schema is mostly arrays of strings — gets its own equally
 * small parser instead of loosening the vault schema. Zero dependencies, read
 * only (the tool never writes an allowlist).
 *
 * <p>Supported values: objects, arrays, strings, integers. Anything else is
 * outside the allowlist schema and is rejected.</p>
 */
final class AllowlistJson {

    private AllowlistJson() {
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

    /** Thrown when the input is not valid JSON or falls outside the allowlist schema. */
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
                    throw error("expected ',' or '}' but found '" + c + "'");
                }
            }
        }

        private List<Object> parseArray() {
            expect('[');
            List<Object> array = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return array;
            }
            while (true) {
                skipWhitespace();
                array.add(parseValue());
                skipWhitespace();
                char c = next();
                if (c == ']') {
                    return array;
                }
                if (c != ',') {
                    throw error("expected ',' or ']' but found '" + c + "'");
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
            if (c == '[') {
                return parseArray();
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return parseInteger();
            }
            throw error("unexpected character '" + c
                    + "' (allowlist schema allows only objects, arrays, strings and integers)");
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
                throw error("invalid number");
            }
            try {
                return Long.parseLong(literal);
            } catch (NumberFormatException e) {
                throw error("integer out of range: " + literal);
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
                default -> throw error("invalid escape '\\" + c + "'");
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
                throw error("expected '" + expected + "' but found '" + c + "'");
            }
        }

        ParseException error(String message) {
            return new ParseException("allowlist JSON error at offset " + pos + ": " + message);
        }
    }
}

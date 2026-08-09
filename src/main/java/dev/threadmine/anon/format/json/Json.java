package dev.threadmine.anon.format.json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Full-grammar JSON reader/writer for {@code jcmd Thread.dump_to_file
 * -format=json} input.
 *
 * <p>Deliberately separate from {@code core.MiniJson}, which stays restricted
 * to the vault schema (objects, strings, integers) and rejects everything else
 * as corruption — a property the vault's auditability argument leans on. A
 * thread dump needs arrays, booleans, nulls and floating-point numbers, so
 * loosening MiniJson would have cost the vault that guarantee. Two small
 * readers, each strict about its own job, beat one permissive reader.</p>
 *
 * <p>Objects keep their key order so masked output stays diffable against the
 * original.</p>
 */
public final class Json {

    private Json() {
    }

    /** Thrown when the input is not valid JSON. */
    public static final class ParseException extends RuntimeException {
        ParseException(String message) {
            super(message);
        }
    }

    public static Object parse(String json) {
        Parser parser = new Parser(json);
        parser.skipWhitespace();
        Object value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw parser.error("trailing content after JSON document");
        }
        return value;
    }

    /** Serializes with the two-space indentation the JDK dumper itself uses. */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, 0);
        sb.append('\n');
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object value, int indent) {
        switch (value) {
            case null -> sb.append("null");
            case String s -> writeString(sb, s);
            case Boolean b -> sb.append(b.toString());
            case Long n -> sb.append(n.toString());
            case Double d -> sb.append(d.toString());
            case Map<?, ?> map -> writeObject(sb, map, indent);
            case List<?> list -> writeArray(sb, list, indent);
            default -> throw new IllegalArgumentException(
                    "unsupported JSON value type: " + value.getClass().getName());
        }
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> object, int indent) {
        if (object.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append("{\n");
        int i = 0;
        for (Map.Entry<?, ?> entry : object.entrySet()) {
            sb.append("  ".repeat(indent + 1));
            writeString(sb, String.valueOf(entry.getKey()));
            sb.append(": ");
            writeValue(sb, entry.getValue(), indent + 1);
            if (++i < object.size()) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append("  ".repeat(indent)).append('}');
    }

    private static void writeArray(StringBuilder sb, List<?> array, int indent) {
        if (array.isEmpty()) {
            sb.append("[]");
            return;
        }
        sb.append("[\n");
        for (int i = 0; i < array.size(); i++) {
            sb.append("  ".repeat(indent + 1));
            writeValue(sb, array.get(i), indent + 1);
            if (i < array.size() - 1) {
                sb.append(',');
            }
            sb.append('\n');
        }
        sb.append("  ".repeat(indent)).append(']');
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

    private static final class Parser {
        private final String input;
        private int pos;

        Parser(String input) {
            this.input = input;
        }

        Object parseValue() {
            char c = peek();
            return switch (c) {
                case '"' -> parseString();
                case '{' -> parseObject();
                case '[' -> parseArray();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        yield parseNumber();
                    }
                    throw error("unexpected character '" + c + "'");
                }
            };
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
                if (object.put(key, value) != null) {
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

        List<Object> parseArray() {
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
                    throw errorAt(pos - 1, "expected ',' or ']' but found '" + c + "'");
                }
            }
        }

        private Object parseLiteral(String literal, Object value) {
            if (!input.startsWith(literal, pos)) {
                throw error("invalid literal, expected " + literal);
            }
            pos += literal.length();
            return value;
        }

        private Object parseNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            boolean floating = false;
            while (!atEnd()) {
                char c = input.charAt(pos);
                if (Character.isDigit(c)) {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    floating = true;
                    pos++;
                } else {
                    break;
                }
            }
            String literal = input.substring(start, pos);
            try {
                return floating ? (Object) Double.valueOf(literal) : (Object) Long.valueOf(literal);
            } catch (NumberFormatException e) {
                throw errorAt(start, "invalid number: " + literal);
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
                // The JDK dumper writes frames as java.base\/java.lang.Thread…
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

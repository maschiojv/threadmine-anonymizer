package dev.threadmine.anon.core;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MiniJsonTest {

    @Test
    void roundTripsVaultShapedDocument() {
        Map<String, Object> collisions = new LinkedHashMap<>();
        collisions.put("t9e2axb7f31", Map.of(
                "original", "pgto-worker",
                "extendedToken", "t9e2a4f1xb7f3190c"));

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", 1L);
        root.put("createdAt", "2026-07-24T12:00:00Z");
        root.put("key", "c29tZS1iYXNlNjQta2V5");
        root.put("map", Map.of("C3f9c1x84d2b", "com.acme.billing.InvoiceService"));
        root.put("collisions", collisions);

        Map<String, Object> parsed = MiniJson.parse(MiniJson.write(root));

        assertEquals(1L, parsed.get("version"));
        assertEquals("2026-07-24T12:00:00Z", parsed.get("createdAt"));
        assertEquals("c29tZS1iYXNlNjQta2V5", parsed.get("key"));
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) parsed.get("map");
        assertEquals("com.acme.billing.InvoiceService", map.get("C3f9c1x84d2b"));
        @SuppressWarnings("unchecked")
        Map<String, Object> col = (Map<String, Object>) parsed.get("collisions");
        @SuppressWarnings("unchecked")
        Map<String, Object> entry = (Map<String, Object>) col.get("t9e2axb7f31");
        assertEquals("t9e2a4f1xb7f3190c", entry.get("extendedToken"));
    }

    @Test
    void escapesAndRestoresHostileStrings() {
        List<String> hostile = List.of(
                "with \"quotes\" inside",
                "back\\slash and \\\" mix",
                "line\nbreak\r\nand\ttab",
                "controlchar and  edge",
                "unicode: café, 東京, emoji 😀",
                "{\"looks\":\"like json\"}",
                "trailing backslash \\");

        for (String original : hostile) {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("value", original);
            Map<String, Object> parsed = MiniJson.parse(MiniJson.write(root));
            assertEquals(original, parsed.get("value"), "round-trip must preserve: " + original);
        }
    }

    @Test
    void roundTripsThousandsOfRandomStrings() {
        Random random = new Random(20260724L);
        for (int i = 0; i < 2000; i++) {
            StringBuilder sb = new StringBuilder();
            int length = random.nextInt(40);
            for (int j = 0; j < length; j++) {
                int codePoint;
                do {
                    codePoint = random.nextInt(0x10FFFF + 1);
                } while (Character.isSurrogate((char) codePoint) && codePoint <= 0xFFFF
                        || !Character.isDefined(codePoint));
                sb.appendCodePoint(codePoint);
            }
            String original = sb.toString();
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("v", original);
            assertEquals(original, MiniJson.parse(MiniJson.write(root)).get("v"),
                    "iteration " + i);
        }
    }

    @Test
    void preservesKeyInsertionOrder() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("zebra", "1");
        root.put("alpha", "2");
        root.put("middle", "3");

        Map<String, Object> parsed = MiniJson.parse(MiniJson.write(root));

        assertEquals(List.of("zebra", "alpha", "middle"), List.copyOf(parsed.keySet()));
    }

    @Test
    void parsesNegativeIntegers() {
        assertEquals(-42L, MiniJson.parse("{\"n\": -42}").get("n"));
    }

    @Test
    void rejectsMalformedJson() {
        List<String> malformed = List.of(
                "",
                "{",
                "{\"a\":}",
                "{\"a\":\"b\"",
                "{\"a\":\"b\"} trailing",
                "not json",
                "{\"a\" \"b\"}",
                "{\"a\":\"unterminated}");
        for (String json : malformed) {
            assertThrows(MiniJson.ParseException.class, () -> MiniJson.parse(json),
                    "must reject: " + json);
        }
    }

    @Test
    void rejectsTypesOutsideTheVaultSchema() {
        // The vault schema only uses objects, strings and integers; anything
        // else in a vault file is corruption and must fail loudly.
        List<String> unsupported = List.of(
                "{\"a\": [1, 2]}",
                "{\"a\": 1.5}",
                "{\"a\": true}",
                "{\"a\": null}");
        for (String json : unsupported) {
            assertThrows(MiniJson.ParseException.class, () -> MiniJson.parse(json),
                    "must reject: " + json);
        }
    }

    @Test
    void rejectsDuplicateKeys() {
        assertThrows(MiniJson.ParseException.class,
                () -> MiniJson.parse("{\"a\":\"1\",\"a\":\"2\"}"));
    }

    @Test
    void parseErrorsCarryPositionInformation() {
        MiniJson.ParseException ex = assertThrows(MiniJson.ParseException.class,
                () -> MiniJson.parse("{\"a\": @}"));
        assertTrue(ex.getMessage().contains("6"), "message should point at offset 6: " + ex.getMessage());
    }
}

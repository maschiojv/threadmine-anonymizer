package dev.threadmine.anon.unmask;

import dev.threadmine.anon.core.Vault;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds vault files directly, so tests can pin exact tokens — including
 * extended forms and originals with awkward characters — without having to
 * provoke an HMAC collision.
 */
final class VaultFixture {

    /** 32 zero bytes in base64: valid key material, irrelevant to reverse lookup. */
    private static final String DUMMY_KEY = "A".repeat(43) + "=";

    private final Map<String, String> map = new LinkedHashMap<>();

    private VaultFixture() {
    }

    static VaultFixture vault() {
        return new VaultFixture();
    }

    VaultFixture with(String token, String original) {
        map.put(token, original);
        return this;
    }

    Vault writeTo(Path file) {
        StringBuilder json = new StringBuilder();
        json.append("{\n  \"version\": 1,\n  \"createdAt\": \"2026-07-24T12:00:00Z\",\n");
        json.append("  \"key\": \"").append(DUMMY_KEY).append("\",\n  \"map\": {\n");
        int i = 0;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            json.append("    \"").append(entry.getKey()).append("\": \"")
                    .append(escape(entry.getValue())).append('"');
            json.append(++i < map.size() ? ",\n" : "\n");
        }
        json.append("  },\n  \"collisions\": {}\n}\n");
        try {
            Files.writeString(file, json.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return Vault.load(file);
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

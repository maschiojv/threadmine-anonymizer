package dev.threadmine.anon.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JsonTextTest {

    @Test
    void escapesTheCharactersJsonRequires() {
        assertEquals("a\\\"b", JsonText.escape("a\"b", false));
        assertEquals("a\\\\b", JsonText.escape("a\\b", false));
        assertEquals("a\\nb", JsonText.escape("a\nb", false));
        assertEquals("a\\rb", JsonText.escape("a\rb", false));
        assertEquals("a\\tb", JsonText.escape("a\tb", false));
        assertEquals("a\\bb", JsonText.escape("a\bb", false));
        assertEquals("a\\fb", JsonText.escape("a\fb", false));
    }

    @Test
    void escapesOtherControlCharactersAsUnicode() {
        assertEquals("a\\u0000b", JsonText.escape("a\u0000b", false));
        assertEquals("a\\u001fb", JsonText.escape("a\u001fb", false));
    }

    @Test
    void leavesOrdinaryTextUntouched() {
        assertEquals("com.acme.LedgerService", JsonText.escape("com.acme.LedgerService", false));
        assertEquals("pgto-worker-1", JsonText.escape("pgto-worker-1", false));
    }

    // Off by default: turning it on for everyone would change vault bytes and
    // the JSON rewriter output, which nobody asked for.
    @Test
    void onlyEscapesAngleBracketsWhenAsked() {
        assertEquals("a<b", JsonText.escape("a<b", false));
        assertEquals("a\\u003cb", JsonText.escape("a<b", true));
        assertEquals("worker\\u003c/script>", JsonText.escape("worker</script>", true));
    }

    /**
     * The vault file must not change a single byte because of this refactor.
     * MiniJson is package-private, which is why this test lives in core.
     */
    @Test
    void miniJsonOutputIsUnchangedByTheExtraction() {
        java.util.Map<String, Object> root = new java.util.LinkedHashMap<>();
        root.put("plain", "pgto-worker-1");
        root.put("hostile", "win\\path\"1\nnewline\u0001");
        root.put("angle", "Comparator<String>");

        String written = MiniJson.write(root);

        assertEquals("pgto-worker-1", MiniJson.parse(written).get("plain"));
        assertEquals("win\\path\"1\nnewline\u0001", MiniJson.parse(written).get("hostile"));
        // Angle brackets stay literal in the vault: escaping them is unmask-only.
        assertEquals("Comparator<String>", MiniJson.parse(written).get("angle"));
        org.junit.jupiter.api.Assertions.assertTrue(written.contains("Comparator<String>"), written);
    }
}

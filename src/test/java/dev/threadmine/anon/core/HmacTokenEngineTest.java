package dev.threadmine.anon.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HmacTokenEngineTest {

    @TempDir
    Path dir;

    private Vault vault;
    private HmacTokenEngine engine;

    @BeforeEach
    void setUp() {
        vault = Vault.create(dir.resolve("vault.json"));
        engine = new HmacTokenEngine(vault);
    }

    @Test
    void standardTokenHasTypeCodePlusFiveHexXFiveHex() {
        assertTrue(engine.tokenize(TokenType.PACKAGE_SEGMENT, "com.acme").matches("p[0-9a-f]{5}x[0-9a-f]{5}"));
        assertTrue(engine.tokenize(TokenType.CLASS_NAME, "com.acme.Foo").matches("C[0-9a-f]{5}x[0-9a-f]{5}"));
        assertTrue(engine.tokenize(TokenType.METHOD_NAME, "com.acme.Foo#bar").matches("m[0-9a-f]{5}x[0-9a-f]{5}"));
        assertTrue(engine.tokenize(TokenType.THREAD_NAME, "pgto-worker").matches("t[0-9a-f]{5}x[0-9a-f]{5}"));
    }

    @Test
    void derivationIsHmacSha256First40BitsAsSpecified() throws GeneralSecurityException {
        // Independent re-implementation of SPEC §1 "Derivação" — pins the
        // wire-level contract so any future engine stays interoperable.
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(vault.key(), "HmacSHA256"));
        byte[] digest = mac.doFinal("C:com.acme.billing.InvoiceService".getBytes(StandardCharsets.UTF_8));
        String hex = HexFormat.of().formatHex(digest, 0, 5);
        String expected = "C" + hex.substring(0, 5) + "x" + hex.substring(5);

        assertEquals(expected, engine.tokenize(TokenType.CLASS_NAME, "com.acme.billing.InvoiceService"));
    }

    @Test
    void tokenizeRegistersTokenForResolve() {
        String token = engine.tokenize(TokenType.CLASS_NAME, "com.acme.Foo");

        assertEquals(Optional.of("com.acme.Foo"), engine.resolve(token));
    }

    @Test
    void resolveIsIdempotentAndUnknownTokensAreEmpty() {
        String token = engine.tokenize(TokenType.THREAD_NAME, "pgto-worker");

        assertEquals(engine.resolve(token), engine.resolve(token), "resolve must be stable");
        assertEquals(Optional.empty(), engine.resolve("t00000x00000"));
        assertEquals(Optional.empty(), engine.resolve("not-a-token"));
    }

    @Test
    void resolveAcceptsTheRouteMarkerSuffix() {
        String token = engine.tokenize(TokenType.THREAD_NAME, "sync-tenant-acme/api/orders");

        assertEquals(Optional.of("sync-tenant-acme/api/orders"), engine.resolve(token + "/q"));
    }

    @Test
    void tokenizeIsIdempotent() {
        String first = engine.tokenize(TokenType.METHOD_NAME, "com.acme.Foo#bar");
        String second = engine.tokenize(TokenType.METHOD_NAME, "com.acme.Foo#bar");

        assertEquals(first, second);
    }

    @Test
    void sameValueUnderDifferentTypesGetsDifferentTokens() {
        String asClass = engine.tokenize(TokenType.CLASS_NAME, "com.acme.Foo");
        String asThread = engine.tokenize(TokenType.THREAD_NAME, "com.acme.Foo");

        assertNotEquals(asClass.substring(1), asThread.substring(1),
                "type is part of the HMAC input, not only the first char");
    }

    @Test
    void sameKeyMeansSameTokensAcrossEngineInstances() {
        String before = engine.tokenize(TokenType.CLASS_NAME, "com.acme.Foo");
        vault.save();

        try (Vault reloaded = Vault.load(dir.resolve("vault.json"))) {
            HmacTokenEngine other = new HmacTokenEngine(reloaded);
            assertEquals(before, other.tokenize(TokenType.CLASS_NAME, "com.acme.Foo"));
        }
    }

    @Test
    void tokenPatternRecognizesStandardExtendedAndRouteForms() {
        Pattern pattern = TokenEngine.tokenPattern();

        assertTrue(pattern.matcher("t9e2a1xb7f31").find());
        assertTrue(pattern.matcher("C1234567x89abcde").find(), "extended form 7x7");
        assertTrue(pattern.matcher("t9e2a1xb7f31/q").find());

        Matcher route = pattern.matcher("blocked on t9e2a1xb7f31/q today");
        assertTrue(route.find());
        assertEquals("t9e2a1xb7f31/q", route.group(), "route marker must be part of the match");
    }

    @Test
    void tokenPatternRejectsNonTokenShapes() {
        Pattern pattern = TokenEngine.tokenPattern();

        assertFalse(pattern.matcher("p123456x654321").find(), "6x6 is not a valid form");
        assertFalse(pattern.matcher("q12345x67890").find(), "unknown type char");
        assertFalse(pattern.matcher("p12345y67890").find(), "wrong separator");
        assertFalse(pattern.matcher("xp12345x67890").find(), "no word boundary before the type char");
        assertFalse(pattern.matcher("java.lang.Thread").find());
    }
}

package dev.threadmine.anon.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Property tests for the 6 token invariants of SPEC §1. Each invariant
 * neutralizes a concrete trap in ThreadMine's detectors (AVALIACAO §1.2):
 * a malformed token would silently disable pool grouping, flame graphs or
 * infra-frame classification. Thousands of realistic identifiers are pushed
 * through the real engine; every produced token must hold every invariant.
 */
class TokenInvariantsPropertyTest {

    /**
     * Infra prefixes that detectors treat as "not application code". A token
     * starting with any of these would flip a busy thread to idle or hide an
     * app frame (PREFIXOS_FRAMES_INFRA, DetectorThreadOrfa, thread-type
     * inference by name prefix).
     */
    private static final List<String> INFRA_PREFIXES = List.of(
            "java.", "javax.", "jakarta.", "jdk.", "sun.", "com.sun.",
            "org.apache", "org.springframework", "org.hibernate", "org.eclipse",
            "io.netty", "okhttp3.", "kotlin.", "scala.",
            "GC ", "C1 ", "C2 ", "VM ", "JIT ", "Sweeper ",
            "Thread-", "ForkJoinPool", "VirtualThread[", "http-nio-", "qtp", "XNIO-");

    private static final int SAMPLE_COUNT = 3000;

    @TempDir
    Path dir;

    private Vault vault;
    private HmacTokenEngine engine;
    private List<Sample> samples;

    private record Sample(TokenType type, String canonicalValue, String token) {
    }

    @BeforeEach
    void tokenizeRealisticCorpus() {
        vault = Vault.create(dir.resolve("vault.json"));
        engine = new HmacTokenEngine(vault);
        Random random = new Random(424242L);
        samples = new ArrayList<>(SAMPLE_COUNT);
        for (int i = 0; i < SAMPLE_COUNT; i++) {
            Sample sample = switch (i % 6) {
                case 0 -> tokenize(TokenType.PACKAGE_SEGMENT, randomPackage(random));
                case 1 -> tokenize(TokenType.CLASS_NAME, randomFqcn(random));
                case 2 -> tokenize(TokenType.METHOD_NAME, randomFqcn(random) + "#" + randomMethod(random));
                case 3 -> tokenize(TokenType.THREAD_NAME, randomPoolPrefix(random));
                case 4 -> tokenize(TokenType.THREAD_NAME, randomRouteName(random));
                default -> tokenize(TokenType.THREAD_NAME, randomPlainThreadName(random));
            };
            samples.add(sample);
        }
    }

    private Sample tokenize(TokenType type, String value) {
        return new Sample(type, value, engine.tokenize(type, value));
    }

    // --- generators -------------------------------------------------------

    private static final String[] WORDS = {
            "acme", "billing", "invoice", "order", "payment", "tenant", "stock",
            "report", "gateway", "ledger", "audit", "cache", "core", "internal",
            "impl", "web", "batch", "worker", "sync", "engine", "adapter", "kafka"};

    private static String word(Random random) {
        return WORDS[random.nextInt(WORDS.length)];
    }

    private static String randomPackage(Random random) {
        int depth = 2 + random.nextInt(4);
        StringBuilder sb = new StringBuilder("com");
        for (int i = 0; i < depth; i++) {
            sb.append('.').append(word(random));
        }
        return sb.toString();
    }

    private static String randomClassName(Random random) {
        String base = capitalize(word(random)) + capitalize(word(random)) + "Service";
        return switch (random.nextInt(4)) {
            case 0 -> base + "$" + capitalize(word(random));
            case 1 -> base + "$$Lambda$" + random.nextInt(500);
            default -> base;
        };
    }

    private static String randomFqcn(Random random) {
        return randomPackage(random) + "." + randomClassName(random);
    }

    private static String randomMethod(Random random) {
        return switch (random.nextInt(4)) {
            case 0 -> "lambda$" + word(random) + "$" + random.nextInt(10);
            default -> "process" + capitalize(word(random));
        };
    }

    private static String randomPoolPrefix(Random random) {
        String separator = random.nextBoolean() ? "-" : "#";
        return word(random) + "-" + word(random) + separator + (1 + random.nextInt(400));
    }

    private static String randomRouteName(Random random) {
        return switch (random.nextInt(3)) {
            case 0 -> "sync-tenant-" + word(random) + "/api/" + word(random) + "?id="
                    + (10000000 + random.nextInt(89999999));
            case 1 -> "req-" + new UUID(random.nextLong(), random.nextLong());
            default -> "session-" + Long.toHexString(random.nextLong()) + Long.toHexString(random.nextLong());
        };
    }

    private static String randomPlainThreadName(Random random) {
        return word(random) + " " + word(random) + " listener";
    }

    private static String capitalize(String value) {
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }

    // --- invariants -------------------------------------------------------

    @Test
    void invariant1_tokenNeverStartsWithAnInfraPrefix() {
        for (Sample sample : samples) {
            for (String prefix : INFRA_PREFIXES) {
                assertFalse(sample.token().startsWith(prefix),
                        () -> "token " + sample.token() + " starts with infra prefix " + prefix);
            }
        }
    }

    @Test
    void invariant2_tokenContainsNoRouteOrQuoteCharacters() {
        Pattern forbidden = Pattern.compile("[/?.\"']");
        for (Sample sample : samples) {
            assertFalse(forbidden.matcher(sample.token()).find(),
                    () -> "token " + sample.token() + " contains a forbidden character");
        }
    }

    @Test
    void invariant3_noLongDigitOrHexRuns() {
        // ehNomeDeRequestOuRota treats >=8 digits or >=16 hex chars as a
        // request-derived name and silently drops the thread from pool
        // grouping; the x separator caps runs at 5 (standard) or 7 (extended).
        Pattern digitRun = Pattern.compile("\\d{8,}");
        Pattern hexRun = Pattern.compile("[0-9a-fA-F]{16,}");
        for (Sample sample : samples) {
            assertFalse(digitRun.matcher(sample.token()).find(),
                    () -> "token " + sample.token() + " has a digit run >= 8");
            assertFalse(hexRun.matcher(sample.token()).find(),
                    () -> "token " + sample.token() + " has a hex run >= 16");
        }
    }

    @Test
    void invariant4_tokenIsWordCharactersOnly() {
        // The flame graph's parseFrame accepts [\w.$]+ segments; a token with
        // other characters would collapse the whole subtree into "(other)".
        for (Sample sample : samples) {
            assertTrue(sample.token().matches("\\w+"),
                    () -> "token " + sample.token() + " is not plain word characters");
        }
    }

    @Test
    void invariant5_sameKeySameCanonicalValueSameToken_acrossEngines() {
        vault.save();
        try (Vault reloaded = Vault.load(dir.resolve("vault.json"))) {
            HmacTokenEngine second = new HmacTokenEngine(reloaded);
            for (Sample sample : samples) {
                assertEquals(sample.token(), second.tokenize(sample.type(), sample.canonicalValue()),
                        () -> "token for " + sample.canonicalValue() + " not stable across engines");
                assertEquals(Optional.of(sample.canonicalValue()), second.resolve(sample.token()));
            }
        }
    }

    @Test
    void invariant6_tokenIsRecognizableInJsonProseAndCsv() {
        Pattern pattern = TokenEngine.tokenPattern();
        for (Sample sample : samples) {
            String token = sample.token();
            List<String> contexts = List.of(
                    "{\"threadNome\":\"" + token + "\",\"estado\":\"BLOCKED\"}",
                    "The thread " + token + " is waiting on a monitor held by " + token + ".",
                    "problema," + token + ",RUNNABLE,42",
                    "at " + token + "." + token + "(" + token + ".java:42)");
            for (String context : contexts) {
                Matcher matcher = pattern.matcher(context);
                assertTrue(matcher.find(), () -> "token " + token + " not found in: " + context);
                assertEquals(token, matcher.group(),
                        () -> "match is not the exact token in: " + context);
            }
        }
    }

    @Test
    void invariant6_routeMarkerFormIsRecognizedAsOneMatch() {
        Pattern pattern = TokenEngine.tokenPattern();
        for (Sample sample : samples) {
            if (sample.type() != TokenType.THREAD_NAME) {
                continue;
            }
            String routeToken = sample.token() + "/q";
            Matcher matcher = pattern.matcher("thread \"" + routeToken + "\" daemon prio=5");
            assertTrue(matcher.find());
            assertEquals(routeToken, matcher.group(), "route marker must belong to the match");
        }
    }
}

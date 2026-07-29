package dev.threadmine.anon.corpus;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.TokenType;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.hotspot.FormatDetector;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.format.hotspot.MaskResult;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Golden tests: masks every fixture of the corpus and validates the output
 * against its expectation YAML (SPEC §6). This is the executable form of the
 * SPEC §5 contract over realistic dumps of every supported dialect.
 */
class CorpusGoldenTest {

    private static final Path FIXTURES = Path.of("corpus", "fixtures");
    private static final Path EXPECTATIONS = Path.of("corpus", "expectations");
    private static final Pattern LOCK_ADDRESS = Pattern.compile("<0x[0-9a-fA-F]+>");
    private static final Pattern MONITOR_ADDRESS = Pattern.compile("(?:monitor|object) 0x[0-9a-fA-F]+");

    @TempDir
    Path tempDir;

    static Stream<String> fixtures() throws IOException {
        try (Stream<Path> files = Files.list(FIXTURES)) {
            List<String> names = files.map(p -> p.getFileName().toString())
                    .filter(n -> n.endsWith(".txt"))
                    .map(n -> n.substring(0, n.length() - 4))
                    .sorted()
                    .toList();
            assertEquals(20, names.size(), "the corpus must have its 20 fixtures");
            return names.stream();
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void fixtureMasksAccordingToItsExpectation(String name) throws IOException {
        String text = Files.readString(FIXTURES.resolve(name + ".txt"), StandardCharsets.UTF_8);
        ExpectationYaml exp = ExpectationYaml.parse(
                Files.readString(EXPECTATIONS.resolve(name + ".yaml"), StandardCharsets.UTF_8));

        assertTrue(FormatDetector.isHotspot(text), "corpus fixture must be detected as HotSpot");

        Vault vault = Vault.create(tempDir.resolve(name + "-vault.json"));
        TokenEngine engine = new HmacTokenEngine(vault);
        MaskResult result = new HotspotRewriter(engine, AllowlistMatcher.fromClasspath()).mask(text);
        String out = result.output();

        // global contract: marker line, nothing redacted, no fixture namespace leak
        assertTrue(out.startsWith("# tm-anon v1\n"), "first output line must be the tm-anon marker");
        assertEquals(0, result.redactedLines(),
                "corpus lines must all be classified; warnings: " + result.warnings());
        assertFalse(out.contains("acme"), "the com.acme namespace must never survive masking");

        for (String anchor : exp.ancorasPreservadas) {
            assertTrue(count(text, anchor) > 0, "anchor missing from fixture itself: " + anchor);
            assertEquals(count(text, anchor), count(out, anchor), "anchor must survive: " + anchor);
        }

        for (String thread : exp.threadsAllowlistVerbatim) {
            String quoted = "\"" + thread + "\"";
            assertTrue(count(text, quoted) > 0, "allowlist thread missing from fixture: " + thread);
            assertEquals(count(text, quoted), count(out, quoted),
                    "allowlist thread must stay verbatim: " + thread);
        }

        for (var entry : exp.threadsTokenizadas.entrySet()) {
            String original = entry.getKey();
            ExpectationYaml.Tokenized spec = entry.getValue();
            String quotedOriginal = "\"" + original + "\"";
            assertTrue(count(text, quotedOriginal) > 0, "tokenized thread missing from fixture: " + original);
            assertEquals(0, count(out, quotedOriginal), "original thread name must not survive: " + original);
            if (original.length() >= 8 || original.contains(" ") || original.contains("/")) {
                assertFalse(out.contains(original), "no fragment of the name may leak: " + original);
            }

            String canonical = original;
            String suffix = "";
            if (spec.preservaSufixo() != null) {
                assertTrue(original.endsWith(spec.preservaSufixo()),
                        "expectation suffix must terminate the name: " + original);
                canonical = original.substring(0, original.length() - spec.preservaSufixo().length());
                suffix = spec.preservaSufixo();
            } else if (spec.marcadorRota()) {
                suffix = "/q";
            }
            String expected = "\"" + engine.tokenize(TokenType.THREAD_NAME, canonical) + suffix + "\"";
            assertEquals(count(text, quotedOriginal), count(out, expected),
                    "every occurrence of " + original + " must become the same token " + expected);
        }

        for (String fqcn : exp.classesTokenizadas) {
            assertTrue(text.contains(fqcn), "class missing from fixture: " + fqcn);
            assertFalse(out.contains(fqcn), "FQCN must not survive: " + fqcn);
            String simpleName = fqcn.substring(fqcn.lastIndexOf('.') + 1);
            assertFalse(out.contains(simpleName), "simple class name must not survive: " + simpleName);
            assertTrue(out.contains(engine.tokenize(TokenType.CLASS_NAME, fqcn)),
                    "deterministic class token must appear for: " + fqcn);
        }

        for (String stripped : exp.linhasStripadas) {
            assertTrue(text.contains(stripped), "strip target missing from fixture: " + stripped);
            assertFalse(out.contains(stripped), "stripped content must not survive: " + stripped);
        }

        // blank lines delimit threads: never created nor removed (SPEC §5.6)
        assertEquals(blankLines(text), blankLines(out), "blank line count must be preserved");

        if (exp.invariantes.contains("enderecos_lock_verbatim")) {
            // Addresses inside the "Locked ownable synchronizers" block are
            // stripped WITH the block (SPEC §5.7); every other address must
            // survive verbatim with its exact count.
            String surviving = withoutSynchronizerBlocks(text);
            assertAddressesVerbatim(surviving, out, LOCK_ADDRESS);
            assertAddressesVerbatim(surviving, out, MONITOR_ADDRESS);
        }
        if (exp.invariantes.contains("ordem_linhas_preservada")) {
            assertEquals(stateLineSequence(text), stateLineSequence(out),
                    "thread state lines must keep their input order");
        }
        if (exp.invariantes.contains("aceita_sem_header_full_thread_dump")) {
            assertFalse(text.contains("Full thread dump"), "fixture must really lack the banner");
        }
    }

    private static String withoutSynchronizerBlocks(String text) {
        StringBuilder sb = new StringBuilder();
        boolean inBlock = false;
        for (String line : text.split("\n", -1)) {
            if (line.trim().equals("Locked ownable synchronizers:")) {
                inBlock = true;
                continue;
            }
            if (inBlock && line.trim().startsWith("-")) {
                continue;
            }
            inBlock = false;
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static void assertAddressesVerbatim(String text, String out, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            String address = matcher.group();
            assertEquals(count(text, address), count(out, address),
                    "address must survive verbatim everywhere: " + address);
        }
    }

    private static List<String> stateLineSequence(String text) {
        return text.lines().map(String::strip)
                .filter(l -> l.startsWith("java.lang.Thread.State:"))
                .toList();
    }

    private static long blankLines(String text) {
        return text.lines().filter(String::isBlank).count();
    }

    private static int count(String haystack, String needle) {
        int count = 0;
        int from = 0;
        while ((from = haystack.indexOf(needle, from)) >= 0) {
            count++;
            from += needle.length();
        }
        return count;
    }
}

package dev.threadmine.anon.corpus;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.TokenType;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.hotspot.FormatDetector;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.format.hotspot.MaskResult;
import dev.threadmine.anon.format.openj9.JavacoreRewriter;
import dev.threadmine.anon.verify.AllowlistLookup;
import dev.threadmine.anon.verify.ComplianceVerifier;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
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
            assertEquals(23, names.size(), "the corpus must have its 23 fixtures (20 HotSpot + 3 javacore)");
            return names.stream();
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void fixtureMasksAccordingToItsExpectation(String name) throws IOException {
        String text = Files.readString(FIXTURES.resolve(name + ".txt"), StandardCharsets.UTF_8);
        ExpectationYaml exp = ExpectationYaml.parse(
                Files.readString(EXPECTATIONS.resolve(name + ".yaml"), StandardCharsets.UTF_8));

        Vault vault = Vault.create(tempDir.resolve(name + "-vault.json"));
        TokenEngine engine = new HmacTokenEngine(vault);

        if (exp.isJavacore()) {
            assertTrue(FormatDetector.isJavacore(text), "javacore fixture must be detected as javacore");
            assertFalse(FormatDetector.isHotspot(text),
                    "the HotSpot detector must not claim a javacore (SPEC 5-B.1)");
            javacoreGolden(text, exp, engine);
            return;
        }

        assertTrue(FormatDetector.isHotspot(text), "corpus fixture must be detected as HotSpot");

        MaskResult result = new HotspotRewriter(engine, AllowlistMatcher.fromClasspath()).mask(text);
        String out = result.output();

        // global contract: marker line, nothing redacted, no fixture namespace leak
        assertEquals("# tm-anon v1", out.lines().findFirst().orElse(""),
                "first output line must be the tm-anon marker");
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

    // --- OpenJ9 javacore golden path (SPEC §5-B) ---------------------------

    private void javacoreGolden(String text, ExpectationYaml exp, TokenEngine engine) {
        AllowlistMatcher matcher = AllowlistMatcher.fromClasspath();
        MaskResult result = new JavacoreRewriter(engine, matcher).mask(text);
        String out = result.output();

        assertEquals("# tm-anon v1", out.lines().findFirst().orElse(""),
                "first output line must be the tm-anon marker (SPEC 5-B.8)");
        assertFalse(out.toLowerCase().contains("acme"),
                "the com.acme namespace must never survive masking");

        // §5-B.1: at least one detection token survives inside the first 4KB
        String probe = out.length() > 4096 ? out.substring(0, 4096) : out;
        assertTrue(exp.ancorasDeteccao4kb.stream().anyMatch(probe::contains),
                "a detection anchor must survive inside the first 4KB: " + exp.ancorasDeteccao4kb);

        // §5-B.2/§5-B.6: forbidden and unknown sections collapse into one marker each
        for (String section : exp.secoesStripadas) {
            String marker = "# [tm-anon: stripped section " + section + "]";
            assertEquals(1, out.lines().filter(l -> l.equals(marker)).count(),
                    "stripped section must collapse into exactly one marker: " + section);
            assertTrue(out.lines().noneMatch(l -> l.startsWith("0SECTION")
                            && sectionNameOf(l).equals(section)),
                    "stripped section header must not survive: " + section);
        }
        for (String section : exp.secoesPreservadas) {
            assertTrue(out.lines().anyMatch(l -> l.startsWith("0SECTION")
                            && sectionNameOf(l).equals(section)),
                    "preserved section header must survive: " + section);
        }

        // §5-B.3/§5-B.6: redacted lines lose their content, and nothing else does
        int expectedRedactions = 0;
        for (String prefix : exp.linhasRedigidas) {
            List<String> originals = text.lines().filter(l -> l.startsWith(prefix)).toList();
            assertFalse(originals.isEmpty(), "redaction target missing from fixture: " + prefix);
            expectedRedactions += originals.size();
            for (String original : originals) {
                assertFalse(out.contains(original), "redacted line must not survive: " + original);
            }
        }
        assertEquals(expectedRedactions, result.redactedLines(),
                "exactly the declared lines fall to redaction; warnings: " + result.warnings());

        // anchors: presence, not count equality — the same name may also appear
        // in a stripped LK section, and a redacted quoteless header may drop a
        // 3XMTHREADINFO occurrence
        for (String anchor : exp.ancorasPreservadas) {
            assertTrue(count(text, anchor) > 0, "anchor missing from fixture itself: " + anchor);
            assertTrue(count(out, anchor) > 0, "anchor must survive: " + anchor);
        }

        for (String threadName : exp.threadsAllowlistVerbatim) {
            String quoted = "\"" + threadName + "\"";
            assertTrue(count(text, quoted) > 0, "allowlist thread missing from fixture: " + threadName);
            assertTrue(count(out, quoted) > 0,
                    "allowlist thread must stay verbatim in the threads section: " + threadName);
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
            assertTrue(count(out, expected) > 0,
                    original + " must appear as its deterministic token " + expected);
        }

        for (String fqcn : exp.classesTokenizadas) {
            String slashed = fqcn.replace('.', '/');
            assertTrue(text.contains(fqcn) || text.contains(slashed),
                    "class missing from fixture: " + fqcn);
            assertFalse(out.contains(fqcn), "FQCN must not survive: " + fqcn);
            assertFalse(out.contains(slashed), "slash-form FQCN must not survive: " + slashed);
            String simpleName = fqcn.substring(fqcn.lastIndexOf('.') + 1);
            // "Application" is also a fixed 3XMCPUTIME category ("current
            // category=\"Application\"") — that JVM vocabulary survives on
            // purpose; the class name must be gone everywhere else.
            assertTrue(out.lines().noneMatch(l -> l.contains(simpleName)
                            && !l.stripLeading().startsWith("3XMCPUTIME")),
                    "simple class name must not survive: " + simpleName);
            assertTrue(out.contains(engine.tokenize(TokenType.CLASS_NAME, fqcn)),
                    "deterministic class token must appear for: " + fqcn);
        }

        assertEquals(blankLines(text), blankLines(out), "blank line count must be preserved");

        javacoreInvariants(text, out, exp, matcher);
    }

    private void javacoreInvariants(String text, String out, ExpectationYaml exp,
                                    AllowlistMatcher matcher) {
        if (exp.idsNativosVerbatim) {
            // §5-B.4: TID/sys_thread_t/native ID/J9VMThread/omrthread_t on the
            // preserved thread lines are addresses, not names — byte-identical.
            Pattern nativeId = Pattern.compile(
                    "(?:TID|sys_thread_t|native ID|J9VMThread|omrthread_t):0x[0-9a-fA-F]+");
            text.lines()
                    .filter(l -> (l.startsWith("3XMTHREADINFO ") && l.contains("\""))
                            || l.startsWith("3XMTHREADBLOCK"))
                    .forEach(line -> {
                        Matcher ids = nativeId.matcher(line);
                        while (ids.find()) {
                            assertTrue(out.contains(ids.group()),
                                    "native id must survive verbatim: " + ids.group());
                        }
                    });
        }

        if (exp.invariantes.contains("moldura_compiled_code_preservada")) {
            // SPEC §5.1: the JIT moulding is structure the ThreadMine parsers
            // read, so it survives verbatim — on the allowlisted frame and on
            // the tokenized one alike. Only the file name in front of it moves.
            assertEquals(count(text, "(Compiled Code)"), count(out, "(Compiled Code)"),
                    "the (Compiled Code) moulding must survive on every frame that had it");
            assertTrue(out.lines().anyMatch(l -> l.contains(".java(Compiled Code))")),
                    "the no-line-number moulding form must survive glued to the source file");
        }

        if (exp.invariantes.contains("ordem_threadinfo_stacktrace_preservada")) {
            assertEquals(threadStackKinds(text), threadStackKinds(out),
                    "relative 3XMTHREADINFO/4XESTACKTRACE order must be preserved (SPEC 5-B.7)");
        }

        if (exp.invariantes.contains("blocked_on_consistente")
                || exp.invariantes.contains("deadlock_nomes_consistentes")) {
            Set<String> headerNames = new java.util.HashSet<>();
            out.lines().filter(l -> l.startsWith("3XMTHREADINFO ")).forEach(l -> {
                Matcher quoted = Pattern.compile("\"([^\"]*)\"").matcher(l);
                while (quoted.find()) {
                    headerNames.add(quoted.group(1));
                }
            });
            out.lines().filter(l -> l.startsWith("3XMTHREADBLOCK")).forEach(l -> {
                Matcher owner = Pattern.compile("Owned by: \"([^\"]*)\"").matcher(l);
                while (owner.find()) {
                    assertTrue(headerNames.contains(owner.group(1)),
                            "Owned by name must carry the owning thread's own header token: " + l);
                }
            });
        }

        if (exp.invariantes.contains("frames_com_barra_tokenizados")) {
            List<String> allowlistFrames = text.lines()
                    .filter(l -> l.startsWith("4XESTACKTRACE")
                            && (l.contains(" at java/") || l.contains(" at jdk/")))
                    .toList();
            assertFalse(allowlistFrames.isEmpty(), "fixture must exercise allowlist slash frames");
            for (String frame : allowlistFrames) {
                assertTrue(out.contains(frame),
                        "allowlist slash frame must survive byte-identical: " + frame);
            }
            assertTrue(out.lines().noneMatch(l -> l.contains("com/")),
                    "no raw slash-form application package may survive");
        }

        ComplianceVerifier verifier = new ComplianceVerifier(lookup(matcher));
        if (exp.invariantes.contains("verify_exit4_se_secao_proibida_sobrevive")) {
            assertFalse(out.contains("LKDEADLOCK"), "no LK line may survive, deadlock block included");
            String tampered = out + "1CICMDLINE     /opt/java/bin/java -Dcorp.db.password=x\n";
            assertFalse(verifier.verify(text, tampered).passed(),
                    "verify must fail when a forbidden section line survives (SPEC 5-B.9)");
        }
        if (exp.invariantes.contains("verify_exit4_se_1tifilename_com_conteudo")) {
            String originalFilename = text.lines()
                    .filter(l -> l.startsWith("1TIFILENAME")).findFirst().orElseThrow();
            String tampered = out.replace("1TIFILENAME    [tm-anon: redacted]", originalFilename);
            assertFalse(tampered.equals(out), "the redacted 1TIFILENAME line must be present to tamper");
            assertFalse(verifier.verify(text, tampered).passed(),
                    "verify must fail when 1TIFILENAME carries content (SPEC 5-B.9)");
        }
    }

    private static List<String> threadStackKinds(String text) {
        return text.lines()
                .filter(l -> (l.startsWith("3XMTHREADINFO ") && l.contains("\""))
                        || l.startsWith("4XESTACKTRACE"))
                .map(l -> l.startsWith("3XMTHREADINFO") ? "T" : "S")
                .toList();
    }

    private static String sectionNameOf(String sectionLine) {
        String rest = sectionLine.substring("0SECTION".length()).strip();
        String suffix = " subcomponent dump routine";
        return rest.endsWith(suffix) ? rest.substring(0, rest.length() - suffix.length()).strip() : rest;
    }

    private static AllowlistLookup lookup(AllowlistMatcher matcher) {
        return new AllowlistLookup() {
            @Override
            public boolean allowsFqcn(String fqcnOrPackage) {
                return matcher.allowsFqcn(fqcnOrPackage);
            }

            @Override
            public boolean allowsThreadName(String name) {
                return matcher.allowsThreadName(name);
            }
        };
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

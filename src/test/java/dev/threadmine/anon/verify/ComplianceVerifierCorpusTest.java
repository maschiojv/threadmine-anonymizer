package dev.threadmine.anon.verify;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.ArrayList;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs the verifier over the whole corpus of realistic dumps. Two properties
 * are checked on every fixture, and together they are what makes the verdict
 * worth trusting:
 *
 * <ul>
 *   <li>an UNMASKED dump must fail — a verifier that says "compliant" for a
 *       raw dump would rubber-stamp a leak;</li>
 *   <li>comparing a file with itself must not break a single anchor or count —
 *       otherwise real mask output would drown in false structural failures.</li>
 * </ul>
 */
class ComplianceVerifierCorpusTest {

    private static final Path FIXTURES = Path.of("corpus", "fixtures");

    private final ComplianceVerifier verifier =
            new ComplianceVerifier(FakeAllowlistMatcher.threadMineDefaults());

    private static List<Path> fixtures() throws IOException {
        try (Stream<Path> files = Files.list(FIXTURES)) {
            return files.filter(p -> p.toString().endsWith(".txt")).sorted().toList();
        }
    }

    @TestFactory
    Stream<DynamicTest> everyFixtureIsRecognizedAsAThreadDump() throws IOException {
        return fixtures().stream().map(fixture -> DynamicTest.dynamicTest(fixture.getFileName().toString(), () -> {
            String dump = Files.readString(fixture, StandardCharsets.UTF_8);
            assertTrue(ComplianceVerifier.looksLikeThreadDump(dump),
                    "the corpus is the reference for what tm-anon must accept");
        }));
    }

    @TestFactory
    Stream<DynamicTest> everyUnmaskedFixtureFailsCompliance() throws IOException {
        return fixtures().stream().map(fixture -> DynamicTest.dynamicTest(fixture.getFileName().toString(), () -> {
            String dump = Files.readString(fixture, StandardCharsets.UTF_8);

            VerifyReport report = verifier.verify(dump, dump);

            assertFalse(report.passed(), "a raw dump must never be reported as compliant");
            assertFalse(report.residualIdentifiers().isEmpty());
            List<String> application = applicationIdentifiers(fixture);
            assertTrue(report.residualIdentifiers().stream()
                            .anyMatch(f -> application.stream().anyMatch(id -> f.value().contains(id))),
                    "the fixture's application identifiers " + application
                            + " must be among the findings: " + report.residualIdentifiers());
        }));
    }

    @TestFactory
    Stream<DynamicTest> structuralChecksNeverFireWhenNothingChanged() throws IOException {
        return fixtures().stream().map(fixture -> DynamicTest.dynamicTest(fixture.getFileName().toString(), () -> {
            String dump = Files.readString(fixture, StandardCharsets.UTF_8);

            VerifyReport report = verifier.verify(dump, dump);

            assertEquals(List.of(), report.brokenAnchors());
            assertTrue(report.counts().allMatch(),
                    "threads/frames/blank lines must be counted identically on both sides");
            assertTrue(report.counts().originalThreads() > 0, "every fixture has threads");
        }));
    }

    /**
     * What the verifier must flag in a raw copy of this fixture: the fictional
     * {@code acme} namespace that the synthetic corpus uses, plus the
     * {@code tokenized_classes} its expectation file declares. The real JDK
     * 21-25 dumps captured for allowlist-v2 have their application classes in
     * the default package ({@code GeradorVirtualThreads}, {@code Pin1}), so
     * {@code acme} alone would miss them.
     */
    private static List<String> applicationIdentifiers(Path fixture) throws IOException {
        List<String> ids = new ArrayList<>(List.of("acme"));
        String name = fixture.getFileName().toString().replaceFirst("\\.txt$", "");
        Path expectation = Path.of("corpus", "expectations", name + ".yaml");
        if (Files.exists(expectation)) {
            boolean inSection = false;
            for (String line : Files.readAllLines(expectation, StandardCharsets.UTF_8)) {
                if (!line.startsWith(" ")) {
                    inSection = line.startsWith("tokenized_classes:");
                    continue;
                }
                if (inSection) {
                    Matcher m = Pattern.compile("^\\s*-\\s*\"?([^\"#]+?)\"?\\s*(#.*)?$").matcher(line);
                    if (m.find()) {
                        ids.add(m.group(1).trim());
                    }
                }
            }
        }
        return ids;
    }
}

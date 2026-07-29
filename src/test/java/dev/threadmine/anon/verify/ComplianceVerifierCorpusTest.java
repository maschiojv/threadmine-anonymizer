package dev.threadmine.anon.verify;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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
            assertTrue(report.residualIdentifiers().stream().anyMatch(f -> f.value().contains("acme")),
                    "the fictional application namespace must be among the findings: "
                            + report.residualIdentifiers());
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
}

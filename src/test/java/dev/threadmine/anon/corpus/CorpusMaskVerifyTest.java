package dev.threadmine.anon.corpus;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.verify.AllowlistLookup;
import dev.threadmine.anon.verify.ComplianceVerifier;
import dev.threadmine.anon.verify.VerifyReport;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

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
 * SPEC §9, end to end, over every dialect in the corpus: {@code mask} output
 * has to satisfy {@code verify} — the same check a user runs before letting a
 * dump leave the machine.
 *
 * <p>The golden tests state what each fixture should become; this one asks the
 * adversarial question instead, and asks it with the shipped allowlist on both
 * sides. That is what makes it catch leaks nobody wrote an expectation for:
 * the JDK 24+ {@code - locked <com.acme.Foo@6e8cf4c6>} monitor line shipped
 * the application class name verbatim, and no per-fixture expectation existed
 * to notice.</p>
 */
class CorpusMaskVerifyTest {

    private static final Path FIXTURES = Path.of("corpus", "fixtures");

    @TempDir
    Path tempDir;

    private static List<Path> fixtures() throws IOException {
        try (Stream<Path> files = Files.list(FIXTURES)) {
            return files.filter(p -> p.toString().endsWith(".txt")).sorted().toList();
        }
    }

    @TestFactory
    Stream<DynamicTest> everyFixtureMasksIntoACompliantDump() throws IOException {
        AllowlistMatcher matcher = AllowlistMatcher.fromClasspath();
        ComplianceVerifier verifier = new ComplianceVerifier(lookup(matcher));

        return fixtures().stream().map(fixture -> {
            String name = fixture.getFileName().toString();
            return DynamicTest.dynamicTest(name, () -> {
                String original = Files.readString(fixture, StandardCharsets.UTF_8);
                Vault vault = Vault.create(tempDir.resolve(name + "-vault.json"));
                TokenEngine engine = new HmacTokenEngine(vault);

                String masked = new HotspotRewriter(engine, matcher).mask(original).output();
                VerifyReport report = verifier.verify(original, masked, engine);

                assertEquals(List.of(), report.residualIdentifiers(),
                        "nothing identifiable may survive masking");
                assertEquals(List.of(), report.brokenAnchors(),
                        "masking must not destroy a structural marker");
                assertTrue(report.counts().allMatch(),
                        "threads/frames/blank lines must survive: " + report.counts());
                assertEquals(0, report.redactedLines(),
                        "no corpus line may fall through to fail-closed redaction");
                assertEquals(List.of(), report.unknownTokens(),
                        "the vault used to mask must reverse every token it produced");
                assertTrue(report.passed());
                assertFalse(masked.contains("acme"), "the fictional namespace must never survive");
            });
        });
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
}

package dev.threadmine.anon.corpus;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Inter-dump determinism (SPEC §1 invariant 5): the same vault must assign the
 * same token to the same canonical value in any dump, forever — that is what
 * keeps ThreadMine diff/timeline working on anonymized input. Different vaults
 * must produce unrelated tokens.
 */
class InterDumpDeterminismTest {

    private static final Path FIXTURES = Path.of("corpus", "fixtures");

    @TempDir
    Path tempDir;

    private String mask(String text, Vault vault) {
        TokenEngine engine = new HmacTokenEngine(vault);
        return new HotspotRewriter(engine, AllowlistMatcher.fromClasspath()).mask(text).output();
    }

    @Test
    void sameVaultSameTokensAcrossRepeatedRunsAndConcatenatedDumps() throws IOException {
        String multiDump = Files.readString(FIXTURES.resolve("multi-dump-3x.txt"), StandardCharsets.UTF_8);
        Vault vault = Vault.create(tempDir.resolve("vault-a.json"));

        String first = mask(multiDump, vault);
        String second = mask(multiDump, vault);

        assertEquals(first, second, "same vault + same input must give byte-identical output");
        // pgto-worker-3 appears once per concatenated dump: 3 identical tokens
        Set<String> workerTokens = new LinkedHashSet<>();
        Matcher m = java.util.regex.Pattern.compile("\"(t[0-9a-f]{5}x[0-9a-f]{5})-3\"").matcher(first);
        int occurrences = 0;
        while (m.find()) {
            workerTokens.add(m.group(1));
            occurrences++;
        }
        assertEquals(3, occurrences, "pgto-worker-3 must appear in each of the 3 dumps");
        assertEquals(1, workerTokens.size(), "all 3 dumps must reuse the same base token");
    }

    @Test
    void sameVaultSameTokensAcrossDifferentDumpFiles() throws IOException {
        // pgto-worker-* appears in several distinct fixtures; the shared vault
        // must assign the same pool-prefix token in all of them.
        String dump17 = Files.readString(FIXTURES.resolve("jstack-jdk17-synchronizers.txt"), StandardCharsets.UTF_8);
        String starvation = Files.readString(FIXTURES.resolve("edge-pool-starvation.txt"), StandardCharsets.UTF_8);
        Vault vault = Vault.create(tempDir.resolve("vault-shared.json"));

        String out17 = mask(dump17, vault);
        String outStarvation = mask(starvation, vault);

        assertEquals(firstWorkerToken(out17), firstWorkerToken(outStarvation),
                "the same pool prefix must map to the same token across dump files");
    }

    @Test
    void differentVaultsProduceDifferentTokens() throws IOException {
        String multiDump = Files.readString(FIXTURES.resolve("multi-dump-3x.txt"), StandardCharsets.UTF_8);

        String outA = mask(multiDump, Vault.create(tempDir.resolve("vault-b.json")));
        String outB = mask(multiDump, Vault.create(tempDir.resolve("vault-c.json")));

        assertNotEquals(outA, outB, "different vault keys must yield different outputs");
        assertNotEquals(firstWorkerToken(outA), firstWorkerToken(outB),
                "the same name must get unrelated tokens under different vault keys");
    }

    private static String firstWorkerToken(String masked) {
        Matcher m = java.util.regex.Pattern.compile("\"(t[0-9a-f]{5}x[0-9a-f]{5})-\\d\"").matcher(masked);
        assertTrue(m.find(), "expected a suffixed thread token in: " + masked.substring(0, Math.min(400, masked.length())));
        assertFalse(m.group(1).isEmpty());
        return m.group(1);
    }
}

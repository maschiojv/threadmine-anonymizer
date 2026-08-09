package dev.threadmine.anon.corpus;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.openj9.JavacoreRewriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Turns the SPEC §5-B "1LKDEADLOCK accepted debt" from prose into a guarantee.
 *
 * <p>Masking strips the whole LOCKS section, so the javacore's explicit
 * {@code 1LKDEADLOCK Deadlock detected !!!} announcement does not survive. The
 * SPEC accepts that on one stated ground: the deadlock is still <em>derivable</em>
 * because every thread keeps its {@code 3XMTHREADBLOCK} line, and those lines
 * cross-reference each other into the same wait-for cycle — which is what
 * {@code ParserOpenJ9Impl} actually reads (it ignores the LK section entirely).
 *
 * <p>That ground was an assumption. This test checks it: it rebuilds the
 * wait-for graph from the MASKED output alone and requires the cycle to still be
 * there, with the owner names matching the thread headers token for token and
 * the two monitors staying distinct. If a future change to the strip rules ever
 * takes the {@code 3XMTHREADBLOCK} lines with it, the debt stops being
 * acceptable and this test says so.</p>
 */
class JavacoreDeadlockSurvivalTest {

    private static final Path FIXTURE =
            Path.of("corpus", "fixtures", "openj9-javacore-deadlock.txt");

    /** {@code 3XMTHREADINFO "name" J9VMThread:0x…} — the thread whose block line follows. */
    private static final Pattern HEADER = Pattern.compile("^3XMTHREADINFO\\s+\"([^\"]*)\"");
    /** {@code 3XMTHREADBLOCK Blocked on: <monitor>@0x… Owned by: "name" (…)}. */
    private static final Pattern BLOCKED = Pattern.compile(
            "^3XMTHREADBLOCK\\s+Blocked on:\\s+(\\S+?)(@0x[0-9a-fA-F]+)\\s+Owned by:\\s+\"([^\"]*)\"");

    @TempDir
    Path tempDir;

    @Test
    void deadlockCycleSurvivesTheStrippedLocksSectionViaThreadBlockLines() throws IOException {
        String original = Files.readString(FIXTURE, StandardCharsets.UTF_8);
        var engine = new HmacTokenEngine(Vault.create(tempDir.resolve("vault.json")));
        String masked = new JavacoreRewriter(engine, AllowlistMatcher.fromClasspath())
                .mask(original).output();

        assertFalse(masked.contains("1LKDEADLOCK"),
                "the LOCKS section must still be stripped - that is the debt being accepted");

        List<Block> blocks = blockedOnEdges(masked);
        assertEquals(2, blocks.size(),
                "both blocked threads must keep their 3XMTHREADBLOCK line: " + blocks);

        // The cycle: each blocked thread waits for a monitor held by the other.
        Map<String, String> waitsFor = new LinkedHashMap<>();
        for (Block block : blocks) {
            waitsFor.put(block.threadName(), block.ownerName());
        }
        assertEquals(2, waitsFor.size(), "the two block lines must belong to two distinct threads");
        assertTrue(hasCycle(waitsFor), "the wait-for graph rebuilt from the masked dump lost its cycle: "
                + waitsFor);

        assertNotEquals(blocks.get(0).monitor(), blocks.get(1).monitor(),
                "the two monitors must stay distinct, or the cycle reads as self-contention");
        assertNotEquals(blocks.get(0).monitorAddress(), blocks.get(1).monitorAddress(),
                "monitor addresses are verbatim (SPEC 5-B.5) and must stay distinct");
    }

    @Test
    void ownerNamesUseTheSameTokensAsTheThreadHeaders() throws IOException {
        String original = Files.readString(FIXTURE, StandardCharsets.UTF_8);
        var engine = new HmacTokenEngine(Vault.create(tempDir.resolve("vault.json")));
        String masked = new JavacoreRewriter(engine, AllowlistMatcher.fromClasspath())
                .mask(original).output();

        Set<String> headerNames = new LinkedHashSet<>();
        for (String line : masked.split("\n", -1)) {
            Matcher header = HEADER.matcher(line);
            if (header.find()) {
                headerNames.add(header.group(1));
            }
        }

        for (Block block : blockedOnEdges(masked)) {
            assertTrue(headerNames.contains(block.ownerName()),
                    "owner \"" + block.ownerName() + "\" has no matching thread header - the "
                            + "correlation the analysis needs is broken; headers: " + headerNames);
            assertTrue(headerNames.contains(block.threadName()),
                    "blocked thread \"" + block.threadName() + "\" lost its header");
        }
    }

    /** Pairs each {@code 3XMTHREADBLOCK} line with the thread header above it. */
    private static List<Block> blockedOnEdges(String masked) {
        List<Block> blocks = new ArrayList<>();
        String currentThread = null;
        for (String line : masked.split("\n", -1)) {
            Matcher header = HEADER.matcher(line);
            if (header.find()) {
                currentThread = header.group(1);
                continue;
            }
            Matcher blocked = BLOCKED.matcher(line);
            if (blocked.find()) {
                blocks.add(new Block(currentThread, blocked.group(1), blocked.group(2), blocked.group(3)));
            }
        }
        return blocks;
    }

    private static boolean hasCycle(Map<String, String> waitsFor) {
        for (String start : waitsFor.keySet()) {
            String at = start;
            for (int hops = 0; hops <= waitsFor.size(); hops++) {
                at = waitsFor.get(at);
                if (at == null) {
                    break;
                }
                if (at.equals(start)) {
                    return true;
                }
            }
        }
        return false;
    }

    private record Block(String threadName, String monitor, String monitorAddress, String ownerName) {
    }
}

package dev.threadmine.anon.cli;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArgsTest {

    private static final Set<String> VALUE_OPTIONS = Set.of("--vault", "-o");
    private static final Set<String> FLAGS = Set.of("--dry-run");

    @Test
    void separatesPositionalsFromOptions() {
        Args args = Args.parse(new String[]{"dump.txt", "-o", "out.txt", "--vault", "v.json"},
                VALUE_OPTIONS, FLAGS);

        assertEquals(List.of("dump.txt"), args.positionals());
        assertEquals("out.txt", args.value("-o").orElseThrow());
        assertEquals("v.json", args.value("--vault").orElseThrow());
    }

    @Test
    void flagsAreBooleanAndDoNotConsumeTheNextArgument() {
        Args args = Args.parse(new String[]{"--dry-run", "dump.txt"}, VALUE_OPTIONS, FLAGS);

        assertTrue(args.flag("--dry-run"));
        assertEquals(List.of("dump.txt"), args.positionals());
    }

    @Test
    void absentOptionsAreEmptyAndAbsentFlagsAreFalse() {
        Args args = Args.parse(new String[]{"dump.txt"}, VALUE_OPTIONS, FLAGS);

        assertTrue(args.value("--vault").isEmpty());
        assertFalse(args.flag("--dry-run"));
    }

    @Test
    void valueOptionWithoutValueIsAUsageError() {
        Args.UsageException e = assertThrows(Args.UsageException.class,
                () -> Args.parse(new String[]{"dump.txt", "--vault"}, VALUE_OPTIONS, FLAGS));

        assertTrue(e.getMessage().contains("--vault"));
    }

    @Test
    void unknownOptionIsAUsageError() {
        Args.UsageException e = assertThrows(Args.UsageException.class,
                () -> Args.parse(new String[]{"--frobnicate"}, VALUE_OPTIONS, FLAGS));

        assertTrue(e.getMessage().contains("--frobnicate"));
    }

    @Test
    void repeatedValueOptionIsAUsageError() {
        assertThrows(Args.UsageException.class,
                () -> Args.parse(new String[]{"--vault", "a", "--vault", "b"}, VALUE_OPTIONS, FLAGS));
    }

    @Test
    void aLoneDashIsTreatedAsPositionalNotAsAnOption() {
        Args args = Args.parse(new String[]{"-"}, VALUE_OPTIONS, FLAGS);

        assertEquals(List.of("-"), args.positionals());
    }
}

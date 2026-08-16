package dev.threadmine.anon.cli;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The help banner used to hardcode "tm-anon", a name that does not exist right
 * after a download: the short form is a shell alias this README suggests, and
 * on Windows there are no shell aliases at all. Somebody who ran the jar and
 * mistyped a command got back a suggestion that did not work either.
 */
class InvocationTest {

    @Test
    @DisplayName("a native image is the binary itself")
    void nativeImageUsesTheBareName() {
        assertEquals("tm-anon", Invocation.resolve("runtime", "irrelevant.jar init"));
    }

    @Test
    @DisplayName("running the jar echoes the jar the user actually launched")
    void jarInvocationKeepsTheJarName() {
        assertEquals("java -jar tm-anon.jar", Invocation.resolve(null, "tm-anon.jar init"));
        assertEquals(
                "java -jar tm-anon-0.2.0.jar",
                Invocation.resolve(null, "target/tm-anon-0.2.0.jar mask dump.txt"));
    }

    @Test
    @DisplayName("the jar path is stripped, on both path separators")
    void jarPathIsReducedToItsFileName() {
        assertEquals(
                "java -jar tm-anon.jar",
                Invocation.resolve(null, "C:\\Users\\you\\Downloads\\tm-anon.jar init"));
        assertEquals(
                "java -jar tm-anon.jar",
                Invocation.resolve(null, "/home/you/tools/tm-anon.jar init"));
    }

    // A path with a space is exactly where a naive split(" ") would produce
    // "java -jar C:\Program".
    @Test
    @DisplayName("a path containing spaces survives")
    void jarPathWithSpacesSurvives() {
        assertEquals(
                "java -jar tm-anon.jar",
                Invocation.resolve(null, "C:\\Program Files\\tm anon\\tm-anon.jar verify a b"));
    }

    @Test
    @DisplayName("anything that is not our jar falls back to the documented form")
    void unknownLaunchersFallBack() {
        // Class on the classpath, an embedding host, a test runner's own jar:
        // echoing those back would be worse than the documented default.
        assertEquals("java -jar tm-anon.jar", Invocation.resolve(null, "dev.threadmine.anon.cli.Main init"));
        assertEquals("java -jar tm-anon.jar", Invocation.resolve(null, "surefirebooter-1234.jar"));
        assertEquals("java -jar tm-anon.jar", Invocation.resolve(null, null));
        assertEquals("java -jar tm-anon.jar", Invocation.resolve(null, "   "));
    }

    @Test
    @DisplayName("the current invocation is resolvable in-process and never blank")
    void currentIsAlwaysUsable() {
        String current = Invocation.current();
        assertEquals(current.trim(), current);
        assertEquals(true, current.contains("tm-anon"));
    }
}

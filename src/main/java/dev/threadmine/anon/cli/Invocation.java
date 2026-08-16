package dev.threadmine.anon.cli;

/**
 * How this process was launched, phrased the way the user would type it again.
 *
 * <p>The help banner used to print {@code tm-anon <command>} unconditionally.
 * That name only exists for someone running a native binary from the PATH, or
 * for someone who created the shell alias the README suggests — and Windows
 * has no shell aliases. For the primary artifact, the jar, the printed command
 * was one nobody could run: mistype a command and the tool answered with
 * another one that also fails.</p>
 */
final class Invocation {

    /** What the README documents, and the answer whenever detection is inconclusive. */
    private static final String DEFAULT = "java -jar tm-anon.jar";

    /** Set to "runtime" by GraalVM while a native image executes. */
    private static final String NATIVE_IMAGE_PROPERTY = "org.graalvm.nativeimage.imagecode";

    private Invocation() {
    }

    /** The invocation of the running process. */
    static String current() {
        return resolve(System.getProperty(NATIVE_IMAGE_PROPERTY), System.getProperty("sun.java.command"));
    }

    /**
     * Pure resolution, so the outcome can be pinned by tests instead of
     * depending on whatever launched the JVM running them.
     *
     * @param nativeImageCode value of {@code org.graalvm.nativeimage.imagecode}, or null
     * @param javaCommand     value of {@code sun.java.command}, or null
     */
    static String resolve(String nativeImageCode, String javaCommand) {
        if (nativeImageCode != null && !nativeImageCode.isBlank()) {
            return "tm-anon";
        }
        String jar = jarFileName(javaCommand);
        return jar == null ? DEFAULT : "java -jar " + jar;
    }

    /**
     * The jar file name out of {@code sun.java.command}, which holds the jar path
     * followed by the program arguments — but only when it is one of ours.
     *
     * <p>Echoing back any jar would turn an embedding host or a test runner's own
     * booter jar into installation advice. Cutting at the first {@code .jar}
     * instead of splitting on spaces keeps {@code C:\Program Files\...} intact.</p>
     */
    private static String jarFileName(String javaCommand) {
        if (javaCommand == null || javaCommand.isBlank()) {
            return null;
        }
        int end = javaCommand.indexOf(".jar");
        if (end < 0) {
            return null;
        }
        String path = javaCommand.substring(0, end + ".jar".length());
        int separator = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        String fileName = path.substring(separator + 1);
        return fileName.startsWith("tm-anon") ? fileName : null;
    }
}

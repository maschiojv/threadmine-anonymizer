package dev.threadmine.anon.verify;

import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.verify.VerifyReport.AnchorCheck;
import dev.threadmine.anon.verify.VerifyReport.Counts;
import dev.threadmine.anon.verify.VerifyReport.Finding;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Answers the only question that matters before a masked dump leaves the
 * machine: is there anything identifiable left in it?
 *
 * <p>The check is deliberately adversarial and runs against the MASKED file
 * alone for part (a): every identifier-shaped thing is pulled out and has to
 * justify itself as a token, as allowlisted public infrastructure, or as dump
 * structure. Anything else is a leak. The original is used only for parts (b)
 * and (c) — anchors and volumetrics — where the point is that masking removed
 * names without removing meaning.</p>
 */
public final class ComplianceVerifier {

    /** Anchored form of the canonical token regex, for whole-atom matching. */
    private static final Pattern TOKEN = Pattern.compile("^(?:" + TokenEngine.TOKEN_PATTERN.pattern() + ")$");

    /** A thread token may carry the route marker and the original {@code [-#]N} suffix (SPEC §5.3). */
    private static final Pattern THREAD_TOKEN = Pattern.compile(
            "^t(?:[0-9a-f]{5}x[0-9a-f]{5}|[0-9a-f]{7}x[0-9a-f]{7})(?:/q)?(?:[-#]\\d+)?$");

    private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"");
    /** {@code (a com.acme.Lock)} in jstack, {@code , a com.acme.Lock)} inside a deadlock block. */
    private static final Pattern LOCK_CLASS = Pattern.compile("[(,]\\s*a\\s+([\\w.$]+)");
    /**
     * {@code com.acme.Lock@1f2e3d} in ThreadMXBean/VisualVM output. The
     * identity hash is at least four hex digits and ends the token, which is
     * what keeps module specs such as {@code java.base@21.0.3/} out.
     */
    private static final Pattern CLASS_AT_HASH =
            Pattern.compile("([A-Za-z_$][\\w.$]*)@([0-9a-fA-F]{4,})(?![\\w.$/@])");
    /** Module or classloader prefix on a frame: {@code java.base@21.0.3/} or {@code app//}. */
    private static final Pattern MODULE_PREFIX = Pattern.compile("^(?:[\\w.$]+//|[\\w.$]+@[\\w.+-]+/)");

    private static final Pattern SEGMENT_SEPARATOR = Pattern.compile("\\.");
    private static final Pattern ATOM_SEPARATOR = Pattern.compile("\\$");
    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final Pattern HEX_ADDRESS = Pattern.compile("0x[0-9a-fA-F]+");

    /**
     * Fragments the rewriter keeps verbatim on purpose (SPEC §5.2), so they are
     * structure rather than leftover names.
     */
    private static final Set<String> STRUCTURAL_ATOMS = Set.of(
            "lambda", "Lambda", "<init>", "<clinit>", "init", "clinit", "java", "class");

    private static final Set<String> NON_LOCATIONS =
            Set.of("Native Method", "Unknown Source", "<generated>", "");

    /**
     * Column-0 token of a forbidden javacore section (SPEC §5-B.9): any depth
     * of the CI/LK/CL/DC/DG/ST families, plus depth-1 XE — the XE section body
     * is all {@code 1XE*} lines, while the XE-family tokens that legitimately
     * live inside the THREADS section ({@code 4XESTACKTRACE},
     * {@code 4XENATIVESTACK}) are depth 4 and must not be flagged.
     */
    private static final Pattern FORBIDDEN_SECTION_TOKEN =
            Pattern.compile("^(?:\\d+(?:CI|LK|CL|DC|DG|ST)[A-Z]|1XE[A-Z])[A-Z0-9]*");

    private static final String FILENAME_TOKEN = "1TIFILENAME";
    private static final String FILENAME_REDACTION = "[tm-anon: redacted]";

    /** The version token the ThreadMine parser reads, and its CI-section source in real javacores. */
    private static final String VERSION_ANCHOR = "1XMJAVAVERSION";
    private static final String CI_VERSION_TOKEN = "1CIJAVAVERSION";

    /** The fixed {@code 3XMCPUTIME} category vocabulary — the only quoted strings allowed there. */
    private static final Set<String> CPU_CATEGORIES =
            Set.of("Application", "Resource-Monitor", "System-JVM", "GC", "JIT");

    private final AllowlistLookup allowlist;

    public ComplianceVerifier(AllowlistLookup allowlist) {
        this.allowlist = Objects.requireNonNull(allowlist);
    }

    /** True when the text is recognizable as a thread dump; false means refuse it (SPEC §4, exit 2). */
    public static boolean looksLikeThreadDump(String text) {
        return DumpScan.of(text).looksLikeThreadDump();
    }

    public VerifyReport verify(String original, String masked) {
        return verify(original, masked, null);
    }

    /**
     * @param engine optional vault-backed engine; when present, tokens in the
     *               masked file that this vault cannot reverse are reported —
     *               a mismatch between the file and the vault kept for it
     */
    public VerifyReport verify(String original, String masked, TokenEngine engine) {
        DumpScan before = DumpScan.of(original);
        DumpScan after = DumpScan.of(masked);

        List<Finding> findings = residualIdentifiers(after);
        List<AnchorCheck> anchors = new ArrayList<>();
        for (String marker : DumpScan.ANCHOR_MARKERS) {
            int inOriginal = versionAwareAnchorCount(marker, before);
            int inMasked = versionAwareAnchorCount(marker, after);
            if (inOriginal > 0 || inMasked > 0) {
                anchors.add(new AnchorCheck(marker, inOriginal, inMasked));
            }
        }

        List<String> tokens = tokensIn(masked);
        Counts counts = new Counts(before.threads(), after.threads(),
                before.frames(), after.frames(),
                before.blankLines(), after.blankLines(),
                tokens.size());

        return new VerifyReport(findings, anchors, counts, unknownTokens(tokens, engine),
                after.strippedLines(), after.redactedLines());
    }

    /**
     * §5-B.2 amendment: a real javacore carries its version only in
     * {@code 1CIJAVAVERSION}, which mask strips with the CI/ENVINFO section and
     * re-emits exactly once as {@code 1XMJAVAVERSION} — the token the
     * ThreadMine parser reads. For the version anchor, a side with no
     * {@code 1XMJAVAVERSION} but at least one {@code 1CIJAVAVERSION} counts as
     * one expected line, so an original/masked pair stays intact while a
     * masked file that DROPPED the version breaks the anchor. Symmetric on
     * purpose: verify(x, x) must never flag anything.
     */
    private static int versionAwareAnchorCount(String marker, DumpScan scan) {
        int count = scan.anchorCount(marker);
        if (marker.equals(VERSION_ANCHOR) && count == 0
                && scan.anchorCount(CI_VERSION_TOKEN) > 0) {
            return 1;
        }
        return count;
    }

    // --- (a) identifiers that survived masking -----------------------------

    private List<Finding> residualIdentifiers(DumpScan masked) {
        List<Finding> findings = new ArrayList<>();
        List<String> lines = masked.collapsedLines();
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isEmpty() || line.startsWith("# ")) {
                // tm-anon's own marker lines: "# tm-anon v1", stripped, redacted.
                continue;
            }
            int lineNumber = i + 1;
            checkJavacoreContract(line, lineNumber, findings);
            if (DumpScan.isFrame(line)) {
                checkFrame(DumpScan.frameBody(line), lineNumber, line, findings);
            }
            checkThreadNames(line, lineNumber, findings);
            checkLockClasses(line, lineNumber, findings);
        }
        return findings;
    }

    /** SPEC §5-B.9: forbidden sections and {@code 1TIFILENAME} content are leaks by definition. */
    private static void checkJavacoreContract(String line, int lineNumber, List<Finding> findings) {
        Matcher forbidden = FORBIDDEN_SECTION_TOKEN.matcher(line);
        if (forbidden.find()) {
            findings.add(new Finding(lineNumber, Finding.Kind.FORBIDDEN_SECTION,
                    forbidden.group(), line));
            return;
        }
        if (line.startsWith(FILENAME_TOKEN)) {
            String rest = line.substring(FILENAME_TOKEN.length()).strip();
            if (!rest.isEmpty() && !rest.equals(FILENAME_REDACTION)) {
                findings.add(new Finding(lineNumber, Finding.Kind.FILENAME_CONTENT, rest, line));
            }
        }
    }

    private void checkFrame(String frame, int lineNumber, String line, List<Finding> findings) {
        String body = stripModulePrefix(frame);
        int parenthesis = body.indexOf('(');
        String qualified = (parenthesis < 0 ? body : body.substring(0, parenthesis)).strip();
        // OpenJ9 modern frames spell the FQCN with slashes; the allowlist speaks
        // dotted form only, so the lookup normalizes. The leak check below still
        // sees the original spelling — a name is a leak in either notation.
        if (allowlist.allowsFqcn(qualified.replace('/', '.'))) {
            // Public infrastructure: the rewriter leaves the whole frame,
            // source file included, exactly as it was.
            return;
        }
        if (!qualified.isEmpty() && !isMaskedIdentifier(qualified)) {
            findings.add(new Finding(lineNumber, Finding.Kind.FRAME_CLASS, qualified, line));
        }
        String location = location(body, parenthesis);
        if (!NON_LOCATIONS.contains(location)) {
            String file = location.contains(":") ? location.substring(0, location.indexOf(':')) : location;
            if (!isMaskedIdentifier(file)) {
                findings.add(new Finding(lineNumber, Finding.Kind.SOURCE_FILE, file, line));
            }
        }
    }

    private static String location(String body, int parenthesis) {
        if (parenthesis < 0) {
            return "";
        }
        int close = body.lastIndexOf(')');
        String inside = close > parenthesis ? body.substring(parenthesis + 1, close) : body.substring(parenthesis + 1);
        return stripModulePrefix(inside.strip());
    }

    private void checkThreadNames(String line, int lineNumber, List<Finding> findings) {
        if (line.contains("java version") || line.startsWith("Full thread dump")) {
            return;
        }
        if (line.startsWith("1TISIGINFO")) {
            // JVM-generated dump-event vocabulary: 'Dump Event "user" (...)'.
            return;
        }
        if (line.startsWith("3XMCPUTIME")) {
            // The only quoted strings allowed here are the JVM's fixed CPU
            // categories; anything else could carry an application name.
            Matcher quoted = QUOTED.matcher(line);
            while (quoted.find()) {
                if (!CPU_CATEGORIES.contains(quoted.group(1))) {
                    findings.add(new Finding(lineNumber, Finding.Kind.THREAD_NAME, quoted.group(1), line));
                }
            }
            return;
        }
        Matcher quoted = QUOTED.matcher(line);
        while (quoted.find()) {
            String name = quoted.group(1);
            if (name.isEmpty() || allowlist.allowsThreadName(name) || THREAD_TOKEN.matcher(name).matches()) {
                continue;
            }
            findings.add(new Finding(lineNumber, Finding.Kind.THREAD_NAME, name, line));
        }
    }

    private void checkLockClasses(String line, int lineNumber, List<Finding> findings) {
        Matcher lock = LOCK_CLASS.matcher(line);
        while (lock.find()) {
            reportClass(lock.group(1), lineNumber, line, findings);
        }
        Matcher atHash = CLASS_AT_HASH.matcher(line);
        while (atHash.find()) {
            reportClass(atHash.group(1), lineNumber, line, findings);
        }
    }

    private void reportClass(String candidate, int lineNumber, String line, List<Finding> findings) {
        if (allowlist.allowsFqcn(candidate) || isMaskedIdentifier(candidate)) {
            return;
        }
        findings.add(new Finding(lineNumber, Finding.Kind.LOCK_CLASS, candidate, line));
    }

    /**
     * Whether every identifier-bearing piece of {@code value} is a token or a
     * fragment the rewriter keeps on purpose. Dots and dollars around the
     * tokens are structure, not names.
     */
    private static boolean isMaskedIdentifier(String value) {
        for (String segment : SEGMENT_SEPARATOR.split(value, -1)) {
            if (!segmentIsSafe(segment)) {
                return false;
            }
        }
        return true;
    }

    /**
     * One dot-separated piece of a qualified name. Everything from the first
     * {@code $$} is a generated-class moulding — {@code $$Lambda/0x…},
     * {@code $$EnhancerBySpringCGLIB$$aa11bb22} — which the rewriter keeps
     * verbatim by design (SPEC §5.2): it names the proxy machinery, not
     * application code, and the ThreadMine parsers read it. Only what precedes
     * the moulding still has to be a token, so an unmasked class wearing a
     * proxy suffix is still reported.
     */
    private static boolean segmentIsSafe(String segment) {
        int moulding = segment.indexOf("$$");
        String base = moulding < 0 ? segment : segment.substring(0, moulding);
        for (String atom : ATOM_SEPARATOR.split(base, -1)) {
            if (!atomIsSafe(atom)) {
                return false;
            }
        }
        return true;
    }

    private static boolean atomIsSafe(String atom) {
        if (atom.isEmpty() || TOKEN.matcher(atom).matches() || DIGITS.matcher(atom).matches()
                || HEX_ADDRESS.matcher(atom).matches() || STRUCTURAL_ATOMS.contains(atom)) {
            return true;
        }
        if (atom.indexOf('/') >= 0) {
            // Proxy/lambda scaffolding such as $$Lambda$123/0x00007f1c2a3b4c.
            for (String part : atom.split("/", -1)) {
                if (!atomIsSafe(part)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private static String stripModulePrefix(String value) {
        Matcher module = MODULE_PREFIX.matcher(value);
        return module.find() ? value.substring(module.end()) : value;
    }

    // --- vault cross-check -------------------------------------------------

    private static List<String> tokensIn(String masked) {
        List<String> tokens = new ArrayList<>();
        Matcher matcher = TokenEngine.TOKEN_PATTERN.matcher(masked);
        while (matcher.find()) {
            tokens.add(matcher.group());
        }
        return tokens;
    }

    private static List<String> unknownTokens(List<String> tokens, TokenEngine engine) {
        if (engine == null) {
            return List.of();
        }
        Set<String> unknown = new LinkedHashSet<>();
        for (String token : tokens) {
            if (engine.resolve(token).isEmpty()) {
                unknown.add(token);
            }
        }
        return List.copyOf(unknown);
    }
}

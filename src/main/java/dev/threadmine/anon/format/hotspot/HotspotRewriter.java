package dev.threadmine.anon.format.hotspot;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.TokenType;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Line-by-line rewriter for HotSpot thread dumps (SPEC §5). Every line is
 * classified by its shape — never by its position, so inverted or concatenated
 * dumps work — and is either preserved verbatim, rewritten with deterministic
 * tokens, stripped, or (fail-closed) redacted. Blank lines are never created
 * nor removed: they delimit threads for the ThreadMine parser.
 */
public final class HotspotRewriter {

    static final String OUTPUT_MARKER = "# tm-anon v1";
    static final String STRIPPED_MARKER = "# [tm-anon: stripped]";
    static final String REDACTED_MARKER = "# [tm-anon: redacted]";

    // --- structure (SPEC §5.6) -------------------------------------------
    private static final Pattern STATE_LINE = Pattern.compile("^\\s*java\\.lang\\.Thread\\.State:.*$");
    private static final Pattern TIMESTAMP =
            Pattern.compile("^\\d{4}-\\d{2}-\\d{2}([ T]\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z?)?$");
    /** jcmd preamble pid ("48350:"/"48350") and version lines ("21.0.3+9-LTS"). */
    private static final Pattern PID_OR_VERSION = Pattern.compile("^\\d[0-9A-Za-z.+_-]*:?$");
    private static final Pattern PINNED = Pattern.compile("^\\s*<pinned:\\s*synchronized>\\s*$");
    private static final Pattern CARRIER =
            Pattern.compile("^(\\s*<virtual thread is mounted on carrier thread \")(.*)(\">\\s*)$");
    private static final Pattern CARRYING = Pattern.compile("^\\s*Carrying virtual thread #\\d+\\s*$");
    private static final Pattern SYNCHRONIZER_COUNT =
            Pattern.compile("^\\s*Number of locked synchronizers = \\d+\\s*$");
    private static final Pattern DASH_NONE = Pattern.compile("^\\s*-\\s+None\\s*$");

    // --- deadlock block (SPEC §5.5) --------------------------------------
    private static final Pattern DEADLOCK_ANNOUNCE = Pattern.compile("^Found (one|a) Java-level deadlock:$");
    private static final Pattern DEADLOCK_RULE = Pattern.compile("^=+$");
    private static final Pattern DEADLOCK_STACK_INFO =
            Pattern.compile("^Java stack information for the threads listed above:$");
    private static final Pattern DEADLOCK_COUNT = Pattern.compile("^Found \\d+ deadlocks?\\.$");
    private static final Pattern DEADLOCK_NAME = Pattern.compile("^\"(.*)\":\\s*$");
    private static final Pattern DEADLOCK_HELD_BY = Pattern.compile("^(\\s*which is held by \")(.*)(\",?\\s*)$");
    private static final Pattern DEADLOCK_MONITOR = Pattern.compile(
            "^(\\s*waiting to lock monitor 0x[0-9a-fA-F]+ \\(object 0x[0-9a-fA-F]+, a )([^),]+)(\\),?\\s*)$");

    // --- thread headers (SPEC §5.3) ---------------------------------------
    private static final Pattern QUOTED_HEADER = Pattern.compile(
            "^\"(.*?)\"(\\s+(?:#\\d|Id=\\d|daemon\\b|virtual\\b|prio=|os_prio=).*)$");
    /**
     * jcmd {@code Thread.dump_to_file -format=text}, all three shapes emitted
     * by {@code jdk.internal.vm.ThreadDumper#dumpThread}: JDK 21..23 printed
     * {@code #N "name"} plus a lowercase {@code virtual} suffix and no state
     * at all; JDK 24+ prints {@code #N "name" [virtual ]STATE <Instant>}. The
     * trailer is enumerated rather than left as {@code .*} so that a line only
     * shaped like a header cannot smuggle text past the fail-closed rule.
     */
    private static final Pattern JCMD_HEADER = Pattern.compile(
            "^(#\\d+\\s+\")(.*?)(\"(?:\\s+(?i:VIRTUAL))?"
                    + "(?:\\s+(?:RUNNABLE|BLOCKED|WAITING|TIMED_WAITING|NEW|TERMINATED))?"
                    + "(?:\\s+\\d{4}-\\d{2}-\\d{2}T[0-9:.]+Z?)?\\s*)$");
    private static final Pattern HEADER_MONITOR_REF =
            Pattern.compile("\\bon ([A-Za-z_$][\\w.$]*)@([0-9a-fA-F]+)");
    private static final Pattern HEADER_OWNED_BY = Pattern.compile("owned by \"([^\"]*)\"");

    // --- thread name heuristics (SPEC §5.3b/c) -----------------------------
    private static final Pattern UUID_LIKE = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern LONG_HEX = Pattern.compile("[0-9a-fA-F]{16,}");
    private static final Pattern LONG_DIGITS = Pattern.compile("\\d{8,}");
    private static final Pattern WEB_EXTENSION =
            Pattern.compile("\\.(x?html?|jsp|jspx|php|do|action|json|xml|css|js|svg|png|gif)\\b");
    private static final Pattern NUMERIC_SUFFIX = Pattern.compile("^(.*)([-#])(\\d+)$");

    // --- locks (SPEC §5.4) --------------------------------------------------
    private static final Pattern LOCK_ANGLE = Pattern.compile(
            "^(\\s*- (?:locked|waiting on|waiting to lock|parking to wait for|waiting to re-lock in wait\\(\\))\\s+)"
                    + "<([^>]+)>(.*)$");
    private static final Pattern LOCK_CLASS_SUFFIX = Pattern.compile("^ \\(a ([^)]+)\\)\\s*$");
    /** jstack monitor address: the only angle content SPEC §5.4 pins as verbatim. */
    private static final Pattern LOCK_ADDRESS = Pattern.compile("^0x[0-9a-fA-F]+$");
    /**
     * {@code Objects.toIdentityString(obj)} — what the JDK 24+ jcmd text dump
     * puts between the angle brackets instead of an address
     * ({@code ThreadDumper#decorateObject}).
     */
    private static final Pattern IDENTITY_STRING = Pattern.compile("^([A-Za-z_$][\\w.$]*)@([0-9a-fA-F]+)$");
    private static final String NO_OBJECT_REFERENCE = "no object reference available";
    /** {@code - parking to wait for <…>, owner #30} in the JDK 24+ text dump. */
    private static final Pattern LOCK_OWNER_TRAILER = Pattern.compile("^,\\s*owner #\\d+$");
    /** A monitor the JIT proved unnecessary; carries no identifier at all. */
    private static final Pattern LOCK_ELIMINATED = Pattern.compile("^\\s*-\\s+lock is eliminated\\s*$");
    private static final Pattern LOCK_MXBEAN = Pattern.compile(
            "^(\\s*-\\s+(?:blocked on|waiting on|locked)\\s+)([A-Za-z_$][\\w.$]*)@([0-9a-fA-F]+)\\s*$");
    private static final Pattern SYNCHRONIZER_ENTRY =
            Pattern.compile("^(\\s*-\\s+)([A-Za-z_$][\\w.$]*)@([0-9a-fA-F]+)\\s*$");

    // --- frames (SPEC §5.1) --------------------------------------------------
    private static final Pattern FRAME = Pattern.compile("^(\\s+)(at\\s+)?([^\\s()]+)\\((.*)\\)$");
    /** Module or classloader prefix: {@code java.base@21.0.3/}, {@code java.base/}, {@code app//}. */
    private static final Pattern QUALIFIER_PREFIX = Pattern.compile(
            "^([A-Za-z][A-Za-z0-9_.]*(?:@[A-Za-z0-9_.+-]+)?/{1,2})(?=[A-Za-z])");
    private static final Pattern SOURCE_FILE = Pattern.compile("^([A-Za-z_$][\\w$]*)\\.java(:\\d+)?$");
    private static final Pattern LAMBDA_METHOD = Pattern.compile("^lambda\\$(.+)\\$(\\d+)$");

    // --- strip (SPEC §5.7) ----------------------------------------------------
    private static final Pattern JNI_REFS = Pattern.compile("^JNI global ref.*$");

    private enum StripBlock { NONE, SMR, SYNCHRONIZERS, HEAP }

    private final TokenEngine engine;
    private final AllowlistMatcher allowlist;

    public HotspotRewriter(TokenEngine engine, AllowlistMatcher allowlist) {
        this.engine = Objects.requireNonNull(engine);
        this.allowlist = Objects.requireNonNull(allowlist);
    }

    public MaskResult mask(String text) {
        String[] lines = text.split("\n", -1);
        List<String> out = new ArrayList<>(lines.length + 1);
        List<String> warnings = new ArrayList<>();
        out.add(OUTPUT_MARKER);

        int preserved = 0;
        int tokenized = 0;
        int stripped = 0;
        int redacted = 0;
        StripBlock stripBlock = StripBlock.NONE;
        boolean lastEmittedWasStripMarker = false;

        for (int i = 0; i < lines.length; i++) {
            String raw = lines[i];
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            String eol = raw.endsWith("\r") ? "\r" : "";

            if (line.isBlank()) {
                stripBlock = StripBlock.NONE;
                out.add(raw);
                lastEmittedWasStripMarker = false;
                preserved++;
                continue;
            }

            if (stripBlock != StripBlock.NONE && continuesStripBlock(stripBlock, line)) {
                if (stripBlock == StripBlock.SMR && line.trim().endsWith("}")) {
                    stripBlock = StripBlock.NONE;
                }
                stripped++;
                lastEmittedWasStripMarker = emitStripMarker(out, lastEmittedWasStripMarker, eol);
                continue;
            }
            stripBlock = StripBlock.NONE;

            StripBlock started = stripBlockStart(line);
            if (started != null) {
                stripBlock = started;
                stripped++;
                lastEmittedWasStripMarker = emitStripMarker(out, lastEmittedWasStripMarker, eol);
                continue;
            }
            if (isStandaloneStrip(line)) {
                stripped++;
                lastEmittedWasStripMarker = emitStripMarker(out, lastEmittedWasStripMarker, eol);
                continue;
            }

            String rewritten = rewriteLine(line);
            if (rewritten == null) {
                redacted++;
                warnings.add("line " + (i + 1) + " not recognized, redacted (fail-closed)");
                out.add(REDACTED_MARKER + eol);
                lastEmittedWasStripMarker = false;
                continue;
            }
            out.add(rewritten + eol);
            lastEmittedWasStripMarker = false;
            if (rewritten.equals(line)) {
                preserved++;
            } else {
                tokenized++;
            }
        }

        return new MaskResult(String.join("\n", out), preserved, tokenized, stripped, redacted,
                List.copyOf(warnings));
    }

    private static boolean emitStripMarker(List<String> out, boolean alreadyEmitted, String eol) {
        if (!alreadyEmitted) {
            out.add(STRIPPED_MARKER + eol);
        }
        return true;
    }

    // --- strip classification ------------------------------------------------

    private static StripBlock stripBlockStart(String line) {
        String trimmed = line.trim();
        if (trimmed.equals("Threads class SMR info:") || trimmed.startsWith("_java_thread_list=")) {
            return StripBlock.SMR;
        }
        if (trimmed.equals("Locked ownable synchronizers:")) {
            return StripBlock.SYNCHRONIZERS;
        }
        if (trimmed.equals("Heap")) {
            return StripBlock.HEAP;
        }
        return null;
    }

    private static boolean continuesStripBlock(StripBlock block, String line) {
        String trimmed = line.trim();
        return switch (block) {
            case SMR -> trimmed.startsWith("_java_thread_list=") || trimmed.startsWith("0x")
                    || trimmed.equals("}");
            case SYNCHRONIZERS -> trimmed.startsWith("-");
            case HEAP -> line.startsWith(" ");
            case NONE -> false;
        };
    }

    private static boolean isStandaloneStrip(String line) {
        String trimmed = line.trim();
        return JNI_REFS.matcher(trimmed).matches()
                || trimmed.startsWith("Compiling:")
                || trimmed.equals("No compile task");
    }

    // --- line classification -------------------------------------------------

    /** Returns the rewritten line, or {@code null} when no rule recognizes it (fail-closed). */
    private String rewriteLine(String line) {
        String trimmed = line.trim();

        // structure preserved verbatim (SPEC §5.6)
        if (trimmed.startsWith("Full thread dump")
                || STATE_LINE.matcher(line).matches()
                || TIMESTAMP.matcher(trimmed).matches()
                || PID_OR_VERSION.matcher(trimmed).matches()
                || PINNED.matcher(line).matches()
                || CARRYING.matcher(line).matches()
                || LOCK_ELIMINATED.matcher(line).matches()
                || SYNCHRONIZER_COUNT.matcher(line).matches()
                || DASH_NONE.matcher(line).matches()
                || DEADLOCK_ANNOUNCE.matcher(trimmed).matches()
                || (DEADLOCK_RULE.matcher(trimmed).matches() && trimmed.length() >= 3)
                || DEADLOCK_STACK_INFO.matcher(trimmed).matches()
                || DEADLOCK_COUNT.matcher(trimmed).matches()) {
            return line;
        }

        Matcher carrier = CARRIER.matcher(line);
        if (carrier.matches()) {
            return carrier.group(1) + rewriteThreadName(carrier.group(2)) + carrier.group(3);
        }

        Matcher quotedHeader = QUOTED_HEADER.matcher(line);
        if (quotedHeader.matches()) {
            return "\"" + rewriteThreadName(quotedHeader.group(1)) + "\""
                    + rewriteHeaderRemainder(quotedHeader.group(2));
        }

        Matcher jcmdHeader = JCMD_HEADER.matcher(line);
        if (jcmdHeader.matches()) {
            return jcmdHeader.group(1) + rewriteThreadName(jcmdHeader.group(2)) + jcmdHeader.group(3);
        }

        Matcher deadlockName = DEADLOCK_NAME.matcher(line);
        if (deadlockName.matches()) {
            return "\"" + rewriteThreadName(deadlockName.group(1)) + "\":";
        }

        Matcher heldBy = DEADLOCK_HELD_BY.matcher(line);
        if (heldBy.matches()) {
            return heldBy.group(1) + rewriteThreadName(heldBy.group(2)) + heldBy.group(3);
        }

        Matcher monitor = DEADLOCK_MONITOR.matcher(line);
        if (monitor.matches()) {
            return monitor.group(1) + rewriteClassReference(monitor.group(2)) + monitor.group(3);
        }

        Matcher lockAngle = LOCK_ANGLE.matcher(line);
        if (lockAngle.matches()) {
            String monitorRef = rewriteMonitorReference(lockAngle.group(2));
            if (monitorRef == null) {
                return null; // unknown angle content; fail closed rather than ship it
            }
            String tail = lockAngle.group(3);
            Matcher lockClass = LOCK_CLASS_SUFFIX.matcher(tail);
            if (lockClass.matches()) {
                tail = " (a " + rewriteClassReference(lockClass.group(1)) + ")";
            } else if (!tail.isBlank() && !LOCK_OWNER_TRAILER.matcher(tail.strip()).matches()) {
                return null; // unknown trailer; fail closed
            }
            return lockAngle.group(1) + "<" + monitorRef + ">" + tail;
        }

        Matcher lockMxbean = LOCK_MXBEAN.matcher(line);
        if (lockMxbean.matches()) {
            return lockMxbean.group(1) + rewriteClassReference(lockMxbean.group(2)) + "@" + lockMxbean.group(3);
        }

        Matcher synchronizerEntry = SYNCHRONIZER_ENTRY.matcher(line);
        if (synchronizerEntry.matches()) {
            return synchronizerEntry.group(1) + rewriteClassReference(synchronizerEntry.group(2))
                    + "@" + synchronizerEntry.group(3);
        }

        Matcher frame = FRAME.matcher(line);
        if (frame.matches() && frame.group(3).indexOf('.') >= 0) {
            return rewriteFrame(frame);
        }

        return null;
    }

    // --- thread names (SPEC §5.3) ---------------------------------------------

    /** Applies the §5.3 cascade: allowlist, route heuristic, numeric suffix, whole name. */
    String rewriteThreadName(String name) {
        if (name.isEmpty() || allowlist.allowsThreadName(name)) {
            return name;
        }
        if (looksLikeRoute(name)) {
            return engine.tokenize(TokenType.THREAD_NAME, name) + "/q";
        }
        Matcher suffix = NUMERIC_SUFFIX.matcher(name);
        if (suffix.matches() && !suffix.group(1).isEmpty()) {
            return engine.tokenize(TokenType.THREAD_NAME, suffix.group(1)) + suffix.group(2) + suffix.group(3);
        }
        return engine.tokenize(TokenType.THREAD_NAME, name);
    }

    private static boolean looksLikeRoute(String name) {
        return name.indexOf('/') >= 0
                || name.indexOf('?') >= 0
                || WEB_EXTENSION.matcher(name).find()
                || UUID_LIKE.matcher(name).find()
                || LONG_HEX.matcher(name).find()
                || LONG_DIGITS.matcher(name).find();
    }

    /** MXBean headers carry {@code on Class@hash} and {@code owned by "name"} references. */
    private String rewriteHeaderRemainder(String remainder) {
        StringBuilder sb = new StringBuilder();
        Matcher monitorRef = HEADER_MONITOR_REF.matcher(remainder);
        while (monitorRef.find()) {
            monitorRef.appendReplacement(sb, Matcher.quoteReplacement(
                    "on " + rewriteClassReference(monitorRef.group(1)) + "@" + monitorRef.group(2)));
        }
        monitorRef.appendTail(sb);
        String withClasses = sb.toString();

        sb = new StringBuilder();
        Matcher ownedBy = HEADER_OWNED_BY.matcher(withClasses);
        while (ownedBy.find()) {
            ownedBy.appendReplacement(sb, Matcher.quoteReplacement(
                    "owned by \"" + rewriteThreadName(ownedBy.group(1)) + "\""));
        }
        ownedBy.appendTail(sb);
        return sb.toString();
    }

    // --- classes and frames (SPEC §5.1/§5.2) -----------------------------------

    /**
     * The content between the angle brackets of a monitor line. jstack writes
     * a raw address there and SPEC §5.4 pins it as verbatim; the JDK 24+ jcmd
     * text dump writes {@code FQCN@identityHash} instead, which carries an
     * application class name and gets the same treatment as any other class
     * reference. Anything else returns {@code null} so the caller redacts the
     * line (SPEC §5.8) — an unrecognized monitor is not worth a leak.
     */
    private String rewriteMonitorReference(String inside) {
        if (LOCK_ADDRESS.matcher(inside).matches() || inside.equals(NO_OBJECT_REFERENCE)) {
            return inside;
        }
        Matcher identity = IDENTITY_STRING.matcher(inside);
        if (identity.matches()) {
            return rewriteClassReference(identity.group(1)) + "@" + identity.group(2);
        }
        return null;
    }

    /** Rewrites a bare FQCN reference (lock lines, deadlock monitors, MXBean headers). */
    String rewriteClassReference(String fqcn) {
        if (allowlist.allowsFqcn(fqcn)) {
            return fqcn;
        }
        int classStart = fqcn.lastIndexOf('.');
        String packagePath = classStart < 0 ? "" : fqcn.substring(0, classStart);
        String classSegment = fqcn.substring(classStart + 1);
        StringBuilder sb = new StringBuilder();
        appendTokenizedPackage(sb, packagePath);
        appendTokenizedClass(sb, packagePath, classSegment);
        return sb.toString();
    }

    private String rewriteFrame(Matcher frame) {
        String indent = frame.group(1);
        String at = frame.group(2) == null ? "" : frame.group(2);
        String qualified = frame.group(3);
        String source = frame.group(4);

        String qualifierPrefix = "";
        Matcher prefix = QUALIFIER_PREFIX.matcher(qualified);
        if (prefix.find()) {
            qualifierPrefix = prefix.group(1);
            qualified = qualified.substring(qualifierPrefix.length());
        }
        String safeQualifierPrefix = rewriteQualifierPrefix(qualifierPrefix);

        int methodDot = qualified.lastIndexOf('.');
        if (methodDot <= 0 || methodDot == qualified.length() - 1) {
            return null; // not a plausible frame; fail closed
        }
        String fqcn = qualified.substring(0, methodDot);
        String method = qualified.substring(methodDot + 1);

        if (allowlist.allowsFqcn(fqcn)) {
            if (safeQualifierPrefix.equals(qualifierPrefix)) {
                return frame.group(0);
            }
            return indent + at + safeQualifierPrefix + qualified + "(" + source + ")";
        }

        int classStart = fqcn.lastIndexOf('.');
        String packagePath = classStart < 0 ? "" : fqcn.substring(0, classStart);
        String classSegment = fqcn.substring(classStart + 1);
        String classBase = mouldingStart(classSegment) < 0
                ? classSegment
                : classSegment.substring(0, mouldingStart(classSegment));
        String canonicalClass = packagePath.isEmpty() ? classBase : packagePath + "." + classBase;

        StringBuilder sb = new StringBuilder(indent).append(at).append(safeQualifierPrefix);
        appendTokenizedPackage(sb, packagePath);
        appendTokenizedClass(sb, packagePath, classSegment);
        sb.append('.').append(rewriteMethod(canonicalClass, method));
        sb.append('(').append(rewriteSource(packagePath, source)).append(')');
        return sb.toString();
    }

    private void appendTokenizedPackage(StringBuilder sb, String packagePath) {
        if (packagePath.isEmpty()) {
            return;
        }
        int from = 0;
        while (from <= packagePath.length()) {
            int next = packagePath.indexOf('.', from);
            int end = next < 0 ? packagePath.length() : next;
            String canonical = packagePath.substring(0, end);
            sb.append(engine.tokenize(TokenType.PACKAGE_SEGMENT, canonical)).append('.');
            if (next < 0) {
                break;
            }
            from = next + 1;
        }
    }

    /**
     * Tokenizes {@code Outer$Inner$1} as one class token per {@code $} part
     * (canonical value = full FQCN up to that part, SPEC §1). A generated-class
     * moulding ({@code $$Lambda...}, {@code $$EnhancerBySpringCGLIB$$hash}, …)
     * is kept verbatim: it names no application code, and its hex is a class
     * address, not a secret.
     */
    private void appendTokenizedClass(StringBuilder sb, String packagePath, String classSegment) {
        int moulding = mouldingStart(classSegment);
        String base = moulding < 0 ? classSegment : classSegment.substring(0, moulding);
        String mould = moulding < 0 ? "" : classSegment.substring(moulding);

        String canonical = packagePath.isEmpty() ? "" : packagePath + ".";
        boolean first = true;
        for (String part : base.split("\\$", -1)) {
            canonical = first ? canonical + part : canonical + "$" + part;
            if (!first) {
                sb.append('$');
            }
            sb.append(engine.tokenize(TokenType.CLASS_NAME, canonical));
            first = false;
        }
        sb.append(mould);
    }

    private static int mouldingStart(String classSegment) {
        return classSegment.indexOf("$$");
    }

    private String rewriteMethod(String canonicalClass, String method) {
        if (method.equals("<init>") || method.equals("<clinit>")) {
            return method;
        }
        Matcher lambda = LAMBDA_METHOD.matcher(method);
        if (lambda.matches()) {
            return "lambda$"
                    + engine.tokenize(TokenType.METHOD_NAME, canonicalClass + "#" + lambda.group(1))
                    + "$" + lambda.group(2);
        }
        return engine.tokenize(TokenType.METHOD_NAME, canonicalClass + "#" + method);
    }

    /**
     * Standard module ({@code java.base@21/}) and classloader ({@code app//})
     * prefixes are preserved; a custom module or named classloader is an
     * application identifier and gets tokenized as a package segment, keeping
     * the version and slash moulding. Not spelled out by SPEC §5.1 (which only
     * pins {@code java.base@21/…} as preserved) — fail-closed choice.
     */
    private String rewriteQualifierPrefix(String qualifierPrefix) {
        if (qualifierPrefix.isEmpty()) {
            return qualifierPrefix;
        }
        int at = qualifierPrefix.indexOf('@');
        int slash = qualifierPrefix.indexOf('/');
        int nameEnd = at >= 0 ? at : slash;
        String name = qualifierPrefix.substring(0, nameEnd);
        if (name.equals("app") || name.equals("platform") || name.equals("bootstrap")
                || allowlist.allowsFqcn(name)) {
            return qualifierPrefix;
        }
        return engine.tokenize(TokenType.PACKAGE_SEGMENT, name) + qualifierPrefix.substring(nameEnd);
    }

    /**
     * Rewrites the parenthesized source of a non-allowlist frame. File names
     * become the class token of {@code <frame package>.<basename>} + literal
     * {@code .java} (SPEC §1); {@code Native Method}, {@code Unknown Source}
     * and {@code <generated>} stay verbatim, including any module prefix.
     */
    private String rewriteSource(String packagePath, String source) {
        String modulePrefix = "";
        Matcher prefix = QUALIFIER_PREFIX.matcher(source);
        if (prefix.find()) {
            modulePrefix = rewriteQualifierPrefix(prefix.group(1));
            source = source.substring(prefix.group(1).length());
        }
        if (source.equals("Native Method") || source.equals("Unknown Source")
                || source.equals("<generated>") || source.isEmpty()) {
            return modulePrefix + source;
        }
        Matcher file = SOURCE_FILE.matcher(source);
        if (file.matches()) {
            String canonical = packagePath.isEmpty() ? file.group(1) : packagePath + "." + file.group(1);
            String lineRef = file.group(2) == null ? "" : file.group(2);
            return modulePrefix + engine.tokenize(TokenType.CLASS_NAME, canonical) + ".java" + lineRef;
        }
        // Unknown source shape: tokenize it whole rather than leak it.
        String canonical = packagePath.isEmpty() ? source : packagePath + "." + source;
        return modulePrefix + engine.tokenize(TokenType.CLASS_NAME, canonical);
    }
}

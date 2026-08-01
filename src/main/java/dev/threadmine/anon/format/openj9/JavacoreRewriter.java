package dev.threadmine.anon.format.openj9;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.core.TokenType;
import dev.threadmine.anon.format.hotspot.HotspotRewriter;
import dev.threadmine.anon.format.hotspot.MaskResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Section-oriented rewriter for OpenJ9 javacores (SPEC §5-B). A javacore is
 * not delimited by blank lines the way a HotSpot dump is: every line opens
 * with a column-0 token ({@code 0SECTION}, {@code 3XMTHREADINFO}, …), sections
 * run from one {@code 0SECTION} line to the next, and the ThreadMine parser
 * closes a thread on the next {@code 3XMTHREADINFO} or EOF (§5-B.7). So this
 * class works per section, not per blank-delimited block:
 *
 * <ul>
 *   <li>a section is preserved only when its body carries TITLE
 *       ({@code TI}) or thread ({@code XM}) family tokens — classification is
 *       by token family, never by the {@code 0SECTION} text, because the
 *       section names changed between generations (classic {@code XM} vs
 *       modern {@code THREADS}) while the token families did not;</li>
 *   <li>every other section — known-forbidden (§5-B.2: CI, LK, CL, DC, DG,
 *       ST, XE) or unknown (§5-B.6, fail-closed by omission) — collapses into
 *       the single line {@code # [tm-anon: stripped section <NAME>]};</li>
 *   <li>inside a preserved section, a line either matches an explicit rule or
 *       is redacted (§5-B.6).</li>
 * </ul>
 *
 * <p>Token assignments are delegated to the HotSpot helpers so that the same
 * canonical value yields the same token in both dialects — that is what keeps
 * ThreadMine's cross-dump comparison working on anonymized javacores.
 * Slash-form identifiers ({@code com/acme/Foo}) are canonicalized with dots
 * before tokenization and the slash is re-emitted as punctuation between
 * tokens, never inside one (SPEC §1 forbids {@code /} in a token).</p>
 */
public final class JavacoreRewriter {

    static final String OUTPUT_MARKER = "# tm-anon v1";
    static final String REDACTED_MARKER = "# [tm-anon: redacted]";
    static final String FILENAME_REDACTION = "[tm-anon: redacted]";

    private static final Pattern SECTION_HEADER = Pattern.compile("^0SECTION\\s+(.*?)\\s*$");
    private static final String SECTION_SUFFIX = " subcomponent dump routine";
    /** Column-0 token: depth digit + uppercase family+name ({@code 3XMTHREADINFO}). */
    private static final Pattern LINE_TOKEN = Pattern.compile("^(\\d+)([A-Z]+)");
    /** {@code NULL} separators carry only rules ({@code ---}/{@code ===}) — never content. */
    private static final Pattern NEUTRAL_NULL = Pattern.compile("^NULL(\\s+[-=]+\\s*)?$");

    // --- TITLE section (§5-B.3) -------------------------------------------
    private static final Set<String> TITLE_PRESERVED_TOKENS = Set.of(
            "1TISIGINFO", "1TIDATETIME", "1TICHARSET", "1TITIMEZONE",
            "1TINANOTIME", "1TIREQFLAGS", "1TIPREPSTATE");
    private static final Pattern TITLE_LINE = Pattern.compile("^(1TI[A-Z0-9]+)\\s.*$");
    private static final Pattern FILENAME_LINE = Pattern.compile("^(1TIFILENAME)(\\s+).*$");

    // --- threads section (§5-B.4/5/7) --------------------------------------
    private static final Pattern THREAD_HEADER = Pattern.compile("^(3XMTHREADINFO\\s+)\"(.*)\"(.*)$");
    /**
     * What may follow the quoted name: VM-generated identity fields only
     * (classic {@code (TID:0x…, sys_thread_t:0x…, state:R, native ID:0x…)},
     * modern {@code J9VMThread:0x…, omrthread_t:0x…, java/lang/Thread:0x…}).
     * Quotes are excluded so nothing name-like can ride along verbatim.
     */
    private static final Pattern THREAD_HEADER_TRAILER =
            Pattern.compile("^[\\sA-Za-z0-9_:,./()=\\-]*$");
    private static final Pattern XM_JAVA_VERSION = Pattern.compile("^1XMJAVAVERSION\\s.*$");
    private static final Pattern XM_LABEL =
            Pattern.compile("^(?:1XMCURTHDINFO|1XMTHDINFO|1XMPOOLINFO)\\s+[A-Za-z :]*$");
    private static final Pattern XM_POOL_COUNT =
            Pattern.compile("^2XMPOOL[A-Z]+\\s+[A-Za-z ]+: \\d+$");
    private static final Pattern XM_FULL_DUMP = Pattern.compile("^2XMFULLTHDDUMP\\s+Full thread dump .*$");
    private static final Pattern JAVA_LTHREAD = Pattern.compile(
            "^3XMJAVALTHREAD\\s+\\(java/lang/Thread getId:0x[0-9a-fA-F]+, isDaemon:(?:true|false)\\)$");
    private static final Pattern THREAD_NATIVE_INFO =
            Pattern.compile("^3XMTHREADINFO[12]\\s+\\([A-Za-z0-9_:, ./x\\-]*\\)$");
    /** The CPU category vocabulary is fixed by the JVM — anything else is not neutral. */
    private static final Pattern CPU_TIME = Pattern.compile(
            "^3XMCPUTIME\\s+CPU usage total: [0-9.]+ secs"
                    + "(?:, current category=\"(?:Application|Resource-Monitor|System-JVM|GC|JIT)\")?$");
    private static final Pattern THREAD_STATE = Pattern.compile(
            "^3XMTHREADINFO3\\s+(?:Java\\.lang\\.Thread\\.State:\\s+[A-Z_]+(?:\\s+\\(.*\\))?"
                    + "|Java callstack:|Native callstack:)$");
    private static final Pattern STACK_FRAME =
            Pattern.compile("^(4XESTACKTRACE\\s+)(at\\s+)([^\\s()]+)\\((.*)\\)$");
    private static final Pattern THREAD_BLOCK = Pattern.compile(
            "^(3XMTHREADBLOCK\\s+Blocked on:\\s+)([^\\s@]+)(@0x[0-9a-fA-F]+)"
                    + "(\\s+Owned by:\\s+\")([^\"]*)(\"\\s*\\(.*\\)\\s*)$");
    private static final Pattern SOURCE_JAVA = Pattern.compile(
            "^([A-Za-z_$][\\w$]*)\\.java(:\\d+)?(\\(Compiled Code\\))?$");
    private static final Pattern LAMBDA_METHOD = Pattern.compile("^lambda\\$(.+)\\$(\\d+)$");
    private static final Set<String> VERBATIM_SOURCES =
            Set.of("Native Method", "Unknown Source", "<generated>", "");

    // --- §5-B.2 amendment: JVM version re-emitted from the stripped section --
    // A real javacore has no 1XMJAVAVERSION: its only version line is
    // 1CIJAVAVERSION, inside the CI/ENVINFO section that §5-B.2 strips whole.
    // Losing it makes ThreadMine parse the masked dump with versaoJava=null —
    // information that is not sensitive (the payload is the JVM's own
    // java.fullversion: version, vendor, OS/arch, public GA/SR build id).
    // The payload is re-emitted right after the strip marker under
    // 1XMJAVAVERSION, the one token ParserOpenJ9Impl reads — re-emitting the
    // original 1CI token would itself be flagged by verify as a surviving
    // forbidden-section line (§5-B.9). Fail-closed guard: each
    // whitespace-separated word must look like version vocabulary; anything
    // path-, env- or hostname-shaped is replaced by a redaction placeholder.
    private static final Pattern CI_JAVA_VERSION = Pattern.compile("^1CIJAVAVERSION\\s+(.*\\S)\\s*$");
    private static final Pattern SAFE_VERSION_WORD =
            Pattern.compile("^[-()A-Za-z0-9][-()A-Za-z0-9._+,]*$");
    /** Two alphabetic runs joined by a dot read as a hostname/domain, never as a version. */
    private static final Pattern DOMAIN_LIKE_WORD = Pattern.compile("[A-Za-z]{2,}\\.[A-Za-z]{2,}");
    /** In-line placeholder; deliberately digit-free so it can never read as a version number. */
    static final String REDACTED_FRAGMENT = "[tm-anon:redacted]";
    private static final String REEMITTED_VERSION_TOKEN = "1XMJAVAVERSION ";

    private enum SectionKind { PREAMBLE, TITLE, THREADS, STRIP }

    private final TokenEngine engine;
    private final AllowlistMatcher allowlist;
    /** Shared §5.3/§5.1 token cascades — same canonical values, same tokens as HotSpot. */
    private final HotspotRewriter helpers;

    public JavacoreRewriter(TokenEngine engine, AllowlistMatcher allowlist) {
        this.engine = Objects.requireNonNull(engine);
        this.allowlist = Objects.requireNonNull(allowlist);
        this.helpers = new HotspotRewriter(engine, allowlist);
    }

    public MaskResult mask(String text) {
        String[] lines = text.split("\n", -1);
        List<String> out = new ArrayList<>(lines.length + 1);
        List<String> warnings = new ArrayList<>();
        out.add(OUTPUT_MARKER + (lines.length > 0 && lines[0].endsWith("\r") ? "\r" : ""));

        int preserved = 0;
        int tokenized = 0;
        int stripped = 0;
        int redacted = 0;
        SectionKind kind = SectionKind.PREAMBLE;
        boolean stripMarkerEmitted = false;
        String sectionName = null;
        boolean hasParserVersionLine = hasParserVersionLine(lines);
        boolean versionReemitted = false;

        for (int i = 0; i < lines.length; i++) {
            String raw = lines[i];
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            String eol = raw.endsWith("\r") ? "\r" : "";

            if (line.isBlank()) {
                // Rare in a javacore (NULL plays this role), but never invent
                // or remove one — same §5.6 discipline as HotSpot.
                out.add(raw);
                preserved++;
                continue;
            }

            Matcher header = SECTION_HEADER.matcher(line);
            if (header.matches()) {
                sectionName = sectionName(header.group(1));
                kind = classify(lines, i + 1);
                stripMarkerEmitted = false;
                if (kind != SectionKind.STRIP) {
                    out.add(raw);
                    preserved++;
                    continue;
                }
            }

            if (kind == SectionKind.STRIP) {
                if (!stripMarkerEmitted) {
                    out.add("# [tm-anon: stripped section " + sectionName + "]" + eol);
                    stripMarkerEmitted = true;
                }
                Matcher version = CI_JAVA_VERSION.matcher(line);
                if (!hasParserVersionLine && !versionReemitted && version.matches()) {
                    String payload = sanitizeVersionPayload(version.group(1));
                    out.add(REEMITTED_VERSION_TOKEN + payload + eol);
                    versionReemitted = true;
                    if (payload.contains(REDACTED_FRAGMENT)) {
                        redacted++;
                        warnings.add("line " + (i + 1) + ": 1CIJAVAVERSION re-emitted as "
                                + "1XMJAVAVERSION with non-version fragment(s) redacted (fail-closed)");
                    } else {
                        preserved++;
                    }
                    continue;
                }
                stripped++;
                continue;
            }

            String rewritten = switch (kind) {
                case TITLE -> rewriteTitleLine(line);
                case THREADS -> rewriteThreadsLine(line);
                case PREAMBLE -> NEUTRAL_NULL.matcher(line).matches() ? line : null;
                case STRIP -> null; // unreachable
            };
            if (rewritten == null) {
                redacted++;
                warnings.add("line " + (i + 1) + " not recognized, redacted (fail-closed)");
                out.add(REDACTED_MARKER + eol);
                continue;
            }
            out.add(rewritten + eol);
            if (rewritten.equals(line)) {
                preserved++;
            } else if (rewritten.endsWith(FILENAME_REDACTION)) {
                redacted++;
                warnings.add("line " + (i + 1) + ": 1TIFILENAME content redacted (local path, SPEC 5-B.3)");
            } else {
                tokenized++;
            }
        }

        return new MaskResult(String.join("\n", out), preserved, tokenized, stripped, redacted,
                List.copyOf(warnings));
    }

    // --- §5-B.2 amendment helpers -------------------------------------------

    /** Whether the dump already carries the line the ThreadMine parser reads. */
    private static boolean hasParserVersionLine(String[] lines) {
        for (String raw : lines) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            if (line.startsWith("1XMJAVAVERSION")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Word-by-word fail-closed filter for the {@code 1CIJAVAVERSION} payload.
     * Version vocabulary ({@code J2RE 1.4.2}, {@code amd64-64},
     * {@code (build 17.0.9+9)}, IBM SR ids like {@code cn142sr1w-20041028})
     * passes verbatim; anything carrying path separators, {@code =}/{@code @},
     * quotes, or a hostname-shaped {@code word.word} run is replaced by a
     * digit-free placeholder so ThreadMine can never read it as a version.
     */
    private static String sanitizeVersionPayload(String payload) {
        StringBuilder sanitized = new StringBuilder(payload.length());
        for (String word : payload.split("\\s+")) {
            if (sanitized.length() > 0) {
                sanitized.append(' ');
            }
            boolean safe = SAFE_VERSION_WORD.matcher(word).matches()
                    && !DOMAIN_LIKE_WORD.matcher(word).find();
            sanitized.append(safe ? word : REDACTED_FRAGMENT);
        }
        return sanitized.toString();
    }

    // --- section machinery ---------------------------------------------------

    private static String sectionName(String headerText) {
        return headerText.endsWith(SECTION_SUFFIX)
                ? headerText.substring(0, headerText.length() - SECTION_SUFFIX.length()).strip()
                : headerText;
    }

    /**
     * Looks ahead to the next {@code 0SECTION} and classifies the body by the
     * token families it carries. {@code XM} wins over {@code TI} (a threads
     * section never carries TITLE tokens, but the priority makes the choice
     * explicit); anything else — including a body with no recognizable tokens —
     * is stripped, which is the §5-B.6 fail-closed default.
     */
    private static SectionKind classify(String[] lines, int from) {
        boolean sawTitle = false;
        for (int i = from; i < lines.length; i++) {
            String line = lines[i].endsWith("\r") ? lines[i].substring(0, lines[i].length() - 1) : lines[i];
            if (line.startsWith("0SECTION")) {
                break;
            }
            Matcher token = LINE_TOKEN.matcher(line);
            if (!token.find()) {
                continue;
            }
            String family = token.group(2);
            if (family.startsWith("XM")) {
                return SectionKind.THREADS;
            }
            if (family.startsWith("TI")) {
                sawTitle = true;
            }
        }
        return sawTitle ? SectionKind.TITLE : SectionKind.STRIP;
    }

    // --- TITLE lines (§5-B.3) ------------------------------------------------

    /** Returns the rewritten line, or {@code null} to redact (fail-closed). */
    private String rewriteTitleLine(String line) {
        if (NEUTRAL_NULL.matcher(line).matches()) {
            return line;
        }
        Matcher filename = FILENAME_LINE.matcher(line);
        if (filename.matches()) {
            // The token survives so the structure is still recognizable, but a
            // javacore path carries hostname/user/deploy layout — never ship it.
            return filename.group(1) + "    " + FILENAME_REDACTION;
        }
        Matcher title = TITLE_LINE.matcher(line);
        if (title.matches() && TITLE_PRESERVED_TOKENS.contains(title.group(1))) {
            return line;
        }
        return null;
    }

    // --- threads section lines (§5-B.4/5/6/7) --------------------------------

    private String rewriteThreadsLine(String line) {
        if (NEUTRAL_NULL.matcher(line).matches()
                || XM_JAVA_VERSION.matcher(line).matches()
                || XM_LABEL.matcher(line).matches()
                || XM_POOL_COUNT.matcher(line).matches()
                || XM_FULL_DUMP.matcher(line).matches()
                || JAVA_LTHREAD.matcher(line).matches()
                || THREAD_NATIVE_INFO.matcher(line).matches()
                || CPU_TIME.matcher(line).matches()
                || THREAD_STATE.matcher(line).matches()) {
            return line;
        }

        Matcher threadHeader = THREAD_HEADER.matcher(line);
        if (threadHeader.matches()) {
            String trailer = threadHeader.group(3);
            if (!THREAD_HEADER_TRAILER.matcher(trailer).matches()) {
                return null; // unexpected content after the name; fail closed
            }
            // §5-B.4: name by the §5.3 cascade, native identity fields
            // (TID/sys_thread_t/native ID/J9VMThread) verbatim in the trailer.
            return threadHeader.group(1) + "\"" + helpers.rewriteThreadName(threadHeader.group(2))
                    + "\"" + trailer;
        }

        Matcher frame = STACK_FRAME.matcher(line);
        if (frame.matches()) {
            return rewriteFrame(frame);
        }

        Matcher block = THREAD_BLOCK.matcher(line);
        if (block.matches()) {
            // §5-B.5: the target is an application class — tokenize; the
            // address and the owner's native ids stay verbatim; the owner NAME
            // gets the same token as its own 3XMTHREADINFO header.
            return block.group(1) + rewriteClassPath(block.group(2)) + block.group(3)
                    + block.group(4) + helpers.rewriteThreadName(block.group(5)) + block.group(6);
        }

        return null;
    }

    /**
     * One {@code 4XESTACKTRACE at …} frame, §5.1 rules. Classic javacores use
     * dotted FQCNs; modern ones use slashes and may append
     * {@code (Compiled Code)} inside the source parenthesis. The canonical
     * values are always the dotted form, so both spellings of the same class
     * yield the same token as a HotSpot dump would.
     */
    private String rewriteFrame(Matcher frame) {
        String qualified = frame.group(3);
        boolean slashForm = qualified.indexOf('/') >= 0;
        String dotted = qualified.replace('/', '.');

        int methodDot = dotted.lastIndexOf('.');
        if (methodDot <= 0 || methodDot == dotted.length() - 1) {
            return null; // not a plausible frame; fail closed
        }
        String fqcn = dotted.substring(0, methodDot);
        String method = dotted.substring(methodDot + 1);

        if (allowlist.allowsFqcn(fqcn)) {
            return frame.group(0);
        }

        String classPath = helpers.rewriteClassReference(fqcn);
        if (slashForm) {
            classPath = classPath.replace('.', '/');
        }
        int moulding = fqcn.indexOf("$$");
        String canonicalClass = moulding < 0 ? fqcn : fqcn.substring(0, moulding);
        int classStart = fqcn.lastIndexOf('.');
        String packagePath = classStart < 0 ? "" : fqcn.substring(0, classStart);

        return frame.group(1) + frame.group(2) + classPath
                + "." + rewriteMethod(canonicalClass, method)
                + "(" + rewriteSource(packagePath, frame.group(4)) + ")";
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

    private String rewriteSource(String packagePath, String source) {
        if (VERBATIM_SOURCES.contains(source)) {
            return source;
        }
        Matcher file = SOURCE_JAVA.matcher(source);
        if (file.matches()) {
            String canonical = packagePath.isEmpty() ? file.group(1) : packagePath + "." + file.group(1);
            String lineRef = file.group(2) == null ? "" : file.group(2);
            String compiled = file.group(3) == null ? "" : file.group(3);
            return engine.tokenize(TokenType.CLASS_NAME, canonical) + ".java" + lineRef + compiled;
        }
        // Unknown source shape: tokenize it whole rather than leak it.
        String canonical = packagePath.isEmpty() ? source : packagePath + "." + source;
        return engine.tokenize(TokenType.CLASS_NAME, canonical);
    }

    /** A bare class reference that may be slash-form ({@code Blocked on:} targets). */
    private String rewriteClassPath(String reference) {
        boolean slashForm = reference.indexOf('/') >= 0;
        String dotted = reference.replace('/', '.');
        if (allowlist.allowsFqcn(dotted)) {
            return reference;
        }
        String rewritten = helpers.rewriteClassReference(dotted);
        return slashForm ? rewritten.replace('.', '/') : rewritten;
    }
}

///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 21+

/*
 * parity.java - end-to-end parity harness for the ThreadMine anonymizer.
 *
 * Proves the central promise ("same detections, same score"): for every corpus
 * fixture, masks the dump with a throwaway vault, uploads BOTH the original and
 * the masked dump to a ThreadMine dev backend as separate analyses, polls until
 * done, downloads problems + health score + JSON export of both, compares them,
 * and finally unmasks the masked export to check the round trip.
 *
 * This file deliberately lives OUTSIDE the Maven build (src/ is covered by a
 * no-network architecture test; java.net.http is allowed only here). Run it as
 * a standalone single-file program:
 *
 *   java e2e/parity.java self-test
 *   java e2e/parity.java run [--base-url URL] [--api-key KEY] [--jar PATH]
 *                            [--fixtures DIR] [--out DIR] [extra-dump.txt ...]
 *
 * Defaults: base-url http://localhost:8090, fixtures corpus/fixtures,
 * jar target/tm-anon-0.1.0-SNAPSHOT.jar, out e2e/out. The API key can also be
 * given via the TM_API_KEY environment variable.
 *
 * Exit codes: 0 = all fixtures IGUAL or EXPECTED deviation; 1 = usage;
 * 2 = at least one UNEXPECTED deviation or infrastructure failure.
 */

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public class parity {

    // ------------------------------------------------------------------
    // Domain model
    // ------------------------------------------------------------------

    /** One detected problem as reported by GET /api/v1/analises/{id}. */
    record Problem(String tipo, String severidade, int threadsAfetadas) {
        String key() {
            return tipo + "/" + severidade + "/" + threadsAfetadas;
        }
    }

    /** The analysis facts we compare between original and masked. */
    record AnalysisFacts(int healthScore, int totalThreads, String formato, List<Problem> problems) {
    }

    enum Verdict { IGUAL, DESVIO_ESPERADO, DESVIO_INESPERADO }

    record Comparison(Verdict verdict, List<String> notes) {
    }

    /**
     * Expected-deviation catalogue - AVALIACAO_ANONIMIZADOR_LOCAL.md section 1.2
     * item 9. These divergences between original and masked results are known
     * consequences of tokenization and are NOT bugs:
     *
     * (a) app frames that accidentally match package-less detection fragments
     *     (PADROES_CONSUMER_IDLE, e.g. "Consumer.receive") stop matching after
     *     tokenization - a FILA_SEM_CONSUMO (or an idle-reclassification echo)
     *     present in the ORIGINAL may be absent in the MASKED result. Benign:
     *     it removes a false positive.
     * (b) a scheduler pool with a custom name prefix falls back to stack-based
     *     detection - SCHEDULER_PROBLEMA may differ in either direction.
     *
     * Anything else that differs is DESVIO_INESPERADO.
     */
    static final Set<String> RULE_A_TYPES = Set.of("FILA_SEM_CONSUMO");
    static final Set<String> RULE_B_TYPES = Set.of("SCHEDULER_PROBLEMA");

    /** Pure comparison logic - unit-tested offline by `self-test`. */
    static Comparison compare(AnalysisFacts original, AnalysisFacts masked) {
        List<String> notes = new ArrayList<>();

        Map<String, Integer> origSet = multiset(original.problems());
        Map<String, Integer> maskSet = multiset(masked.problems());

        // Problems only in the original / only in the masked result.
        Map<String, Integer> onlyOrig = diff(origSet, maskSet);
        Map<String, Integer> onlyMask = diff(maskSet, origSet);

        boolean problemsEqual = onlyOrig.isEmpty() && onlyMask.isEmpty();
        boolean healthEqual = original.healthScore() == masked.healthScore();
        boolean threadsEqual = original.totalThreads() == masked.totalThreads();
        boolean formatEqual = Objects.equals(original.formato(), masked.formato());

        if (!threadsEqual) {
            notes.add("thread count differs: original=" + original.totalThreads()
                    + " masked=" + masked.totalThreads());
            return new Comparison(Verdict.DESVIO_INESPERADO, notes);
        }
        if (!formatEqual) {
            notes.add("detected format differs: original=" + original.formato()
                    + " masked=" + masked.formato());
            return new Comparison(Verdict.DESVIO_INESPERADO, notes);
        }

        if (problemsEqual && healthEqual) {
            return new Comparison(Verdict.IGUAL, notes);
        }

        if (problemsEqual) { // health differs with identical problems -> not explainable
            notes.add("health score differs with identical problems: original="
                    + original.healthScore() + " masked=" + masked.healthScore());
            return new Comparison(Verdict.DESVIO_INESPERADO, notes);
        }

        // Classify every differing problem entry against the expected rules.
        boolean allExpected = true;
        for (var e : onlyOrig.entrySet()) {
            String tipo = e.getKey().split("/")[0];
            if (RULE_A_TYPES.contains(tipo)) {
                notes.add("expected (rule a): '" + e.getKey() + "' present only in ORIGINAL"
                        + " - package-less fragment match removed by tokenization");
            } else if (RULE_B_TYPES.contains(tipo)) {
                notes.add("expected (rule b): '" + e.getKey() + "' present only in ORIGINAL"
                        + " - scheduler custom prefix now relies on stack fallback");
            } else {
                notes.add("UNEXPECTED: '" + e.getKey() + "' present only in ORIGINAL");
                allExpected = false;
            }
        }
        for (var e : onlyMask.entrySet()) {
            String tipo = e.getKey().split("/")[0];
            if (RULE_B_TYPES.contains(tipo)) {
                notes.add("expected (rule b): '" + e.getKey() + "' present only in MASKED"
                        + " - scheduler custom prefix now relies on stack fallback");
            } else {
                notes.add("UNEXPECTED: '" + e.getKey() + "' present only in MASKED");
                allExpected = false;
            }
        }
        if (!healthEqual) {
            notes.add("health score differs (side effect of the deviations above): original="
                    + original.healthScore() + " masked=" + masked.healthScore());
        }
        return new Comparison(allExpected ? Verdict.DESVIO_ESPERADO : Verdict.DESVIO_INESPERADO, notes);
    }

    static Map<String, Integer> multiset(List<Problem> problems) {
        Map<String, Integer> m = new TreeMap<>();
        for (Problem p : problems) {
            m.merge(p.key(), 1, Integer::sum);
        }
        return m;
    }

    /** Entries of a whose count exceeds their count in b. */
    static Map<String, Integer> diff(Map<String, Integer> a, Map<String, Integer> b) {
        Map<String, Integer> out = new TreeMap<>();
        for (var e : a.entrySet()) {
            int extra = e.getValue() - b.getOrDefault(e.getKey(), 0);
            if (extra > 0) {
                out.put(e.getKey(), extra);
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Round-trip check (pure part - unit-tested offline)
    // ------------------------------------------------------------------

    /**
     * Compares the thread-name sets of the original export and the unmasked
     * masked export. After a correct unmask they must be identical.
     */
    record RoundTrip(boolean ok, List<String> missing, List<String> unexpected, int total) {
    }

    static RoundTrip roundTrip(Set<String> originalNames, Set<String> unmaskedNames) {
        List<String> missing = new ArrayList<>();
        List<String> unexpected = new ArrayList<>();
        for (String n : originalNames) {
            if (!unmaskedNames.contains(n)) {
                missing.add(n);
            }
        }
        for (String n : unmaskedNames) {
            if (!originalNames.contains(n)) {
                unexpected.add(n);
            }
        }
        return new RoundTrip(missing.isEmpty() && unexpected.isEmpty(),
                missing, unexpected, originalNames.size());
    }

    // ------------------------------------------------------------------
    // Minimal JSON parser (no dependencies; jbang not required)
    // ------------------------------------------------------------------

    static final class Json {
        private final String s;
        private int i;

        private Json(String s) {
            this.s = s;
        }

        static Object parse(String text) {
            Json j = new Json(text);
            j.ws();
            Object v = j.value();
            j.ws();
            if (j.i < j.s.length()) {
                throw new IllegalArgumentException("trailing content at " + j.i);
            }
            return v;
        }

        private Object value() {
            char c = s.charAt(i);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> lit("true", Boolean.TRUE);
                case 'f' -> lit("false", Boolean.FALSE);
                case 'n' -> lit("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // {
            ws();
            if (s.charAt(i) == '}') { i++; return m; }
            while (true) {
                ws();
                String k = string();
                ws();
                expect(':');
                ws();
                m.put(k, value());
                ws();
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw new IllegalArgumentException("expected , or } at " + (i - 1));
            }
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++; // [
            ws();
            if (s.charAt(i) == ']') { i++; return l; }
            while (true) {
                ws();
                l.add(value());
                ws();
                char c = s.charAt(i++);
                if (c == ']') return l;
                if (c != ',') throw new IllegalArgumentException("expected , or ] at " + (i - 1));
            }
        }

        private String string() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"' -> b.append('"');
                        case '\\' -> b.append('\\');
                        case '/' -> b.append('/');
                        case 'b' -> b.append('\b');
                        case 'f' -> b.append('\f');
                        case 'n' -> b.append('\n');
                        case 'r' -> b.append('\r');
                        case 't' -> b.append('\t');
                        case 'u' -> {
                            b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                        }
                        default -> throw new IllegalArgumentException("bad escape \\" + e);
                    }
                } else {
                    b.append(c);
                }
            }
        }

        private Object number() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            String n = s.substring(start, i);
            if (n.indexOf('.') < 0 && n.indexOf('e') < 0 && n.indexOf('E') < 0) {
                return Long.parseLong(n);
            }
            return Double.parseDouble(n);
        }

        private Object lit(String word, Object v) {
            if (!s.startsWith(word, i)) throw new IllegalArgumentException("bad literal at " + i);
            i += word.length();
            return v;
        }

        private void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        private void expect(char c) {
            if (s.charAt(i) != c) throw new IllegalArgumentException("expected " + c + " at " + i);
            i++;
        }
    }

    // ------------------------------------------------------------------
    // Facts extraction from API payloads (pure - unit-tested offline)
    // ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    static AnalysisFacts facts(String detailJson) {
        Map<String, Object> d = (Map<String, Object>) Json.parse(detailJson);
        int health = ((Number) d.getOrDefault("healthScore", -1L)).intValue();
        int threads = ((Number) d.getOrDefault("totalThreads", -1L)).intValue();
        String formato = (String) d.get("formatoDetectado");
        List<Problem> problems = new ArrayList<>();
        Map<String, Object> pd = (Map<String, Object>) d.get("problemasDetectados");
        if (pd != null && pd.get("problemas") != null) {
            for (Object o : (List<Object>) pd.get("problemas")) {
                Map<String, Object> p = (Map<String, Object>) o;
                Map<String, Object> ev = (Map<String, Object>) p.get("evidencia");
                int afetadas = ev == null ? 0
                        : ((Number) ev.getOrDefault("quantidadeThreadsAfetadas", 0L)).intValue();
                problems.add(new Problem((String) p.get("tipo"), (String) p.get("severidade"), afetadas));
            }
        }
        return new AnalysisFacts(health, threads, formato, problems);
    }

    @SuppressWarnings("unchecked")
    static Set<String> exportThreadNames(String exportJson) {
        Map<String, Object> d = (Map<String, Object>) Json.parse(exportJson);
        Set<String> names = new TreeSet<>();
        List<Object> threads = (List<Object>) d.getOrDefault("threads", List.of());
        for (Object o : threads) {
            names.add(String.valueOf(((Map<String, Object>) o).get("nome")));
        }
        return names;
    }

    // ------------------------------------------------------------------
    // HTTP + CLI plumbing (network code lives ONLY in this file, never src/)
    // ------------------------------------------------------------------

    static HttpClient http;
    static String baseUrl;
    static String apiKey;

    static HttpResponse<String> get(String path) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + apiKey)
                .timeout(Duration.ofSeconds(60))
                .GET().build();
        return http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    /** POST /api/v1/analises/captura with 429 retry (honors Retry-After). */
    static String upload(String title, byte[] dump) throws IOException, InterruptedException {
        String body = "{\"titulo\":" + q(title)
                + ",\"origem\":\"API\",\"conteudoBase64\":"
                + q(Base64.getEncoder().encodeToString(dump)) + "}";
        for (int attempt = 1; attempt <= 6; attempt++) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/analises/captura"))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(60))
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (res.statusCode() == 202) {
                Map<String, Object> r = castMap(Json.parse(res.body()));
                return (String) r.get("id");
            }
            if (res.statusCode() == 429) {
                long wait = res.headers().firstValue("Retry-After").map(Long::parseLong).orElse(10L);
                System.out.println("    429 rate-limited, waiting " + wait + "s (attempt " + attempt + ")");
                Thread.sleep(Duration.ofSeconds(Math.max(1, wait)));
                continue;
            }
            throw new IOException("upload failed: HTTP " + res.statusCode() + " " + res.body());
        }
        throw new IOException("upload failed: still rate-limited after retries");
    }

    static String pollUntilDone(String id, Duration timeout) throws IOException, InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            HttpResponse<String> res = get("/api/v1/analises/" + id);
            if (res.statusCode() != 200) {
                throw new IOException("poll failed: HTTP " + res.statusCode() + " " + res.body());
            }
            String status = (String) castMap(Json.parse(res.body())).get("status");
            switch (status) {
                case "CONCLUIDA" -> { return res.body(); }
                case "FALHA", "CANCELADA" ->
                        throw new IOException("analysis " + id + " ended with status " + status);
                default -> Thread.sleep(2000);
            }
        }
        throw new IOException("analysis " + id + " did not finish within " + timeout);
    }

    static String exportJson(String id) throws IOException, InterruptedException {
        HttpResponse<String> res = get("/api/v1/analises/" + id + "/exportar?formato="
                + URLEncoder.encode("json", StandardCharsets.UTF_8));
        if (res.statusCode() != 200) {
            throw new IOException("export failed: HTTP " + res.statusCode() + " " + res.body());
        }
        return res.body();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> castMap(Object o) {
        return (Map<String, Object>) o;
    }

    static String q(String v) {
        StringBuilder b = new StringBuilder("\"");
        for (int k = 0; k < v.length(); k++) {
            char c = v.charAt(k);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        return b.append('"').toString();
    }

    static int cli(Path jar, Path workDir, String... args) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>(List.of("java", "-jar", jar.toAbsolutePath().toString()));
        cmd.addAll(List.of(args));
        Process p = new ProcessBuilder(cmd)
                .directory(workDir.toFile())
                .redirectErrorStream(true)
                .start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        if (code != 0) {
            System.out.println("    tm-anon " + String.join(" ", args) + " -> exit " + code);
            System.out.println(out.indent(6));
        }
        return code;
    }

    // ------------------------------------------------------------------
    // Runner
    // ------------------------------------------------------------------

    record FixtureResult(String fixture, AnalysisFacts original, AnalysisFacts masked,
                         Comparison comparison, RoundTrip roundTrip, String error) {
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("self-test")) {
            System.exit(selfTest());
        }
        if (args.length == 0 || !args[0].equals("run")) {
            System.err.println("usage: java e2e/parity.java (run|self-test) [options]");
            System.exit(1);
        }

        baseUrl = "http://localhost:8090";
        apiKey = System.getenv("TM_API_KEY");
        Path jar = Path.of("target/tm-anon-0.1.0-SNAPSHOT.jar");
        Path fixturesDir = Path.of("corpus/fixtures");
        Path outDir = Path.of("e2e/out");
        List<Path> extraDumps = new ArrayList<>();

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--base-url" -> baseUrl = args[++i];
                case "--api-key" -> apiKey = args[++i];
                case "--jar" -> jar = Path.of(args[++i]);
                case "--fixtures" -> fixturesDir = Path.of(args[++i]);
                case "--out" -> outDir = Path.of(args[++i]);
                default -> extraDumps.add(Path.of(args[i]));
            }
        }
        if (apiKey == null || apiKey.isBlank()) {
            System.err.println("missing API key: pass --api-key or set TM_API_KEY");
            System.exit(1);
        }
        if (!Files.isRegularFile(jar)) {
            System.err.println("fat jar not found: " + jar + " - run ./mvnw -DskipTests package first");
            System.exit(1);
        }

        http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

        HttpResponse<String> health = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/actuator/health")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (health.statusCode() != 200) {
            System.err.println("backend not healthy at " + baseUrl + ": HTTP " + health.statusCode());
            System.exit(2);
        }

        Files.createDirectories(outDir);
        Path vault = outDir.resolve("vault.json");
        Path cwd = Path.of(".").toAbsolutePath().normalize();
        if (!Files.exists(vault)) {
            if (cli(jar, cwd, "init", "--vault", vault.toString()) != 0) {
                System.err.println("vault init failed");
                System.exit(2);
            }
        }

        List<Path> dumps = new ArrayList<>();
        try (var stream = Files.list(fixturesDir)) {
            stream.filter(p -> p.getFileName().toString().endsWith(".txt"))
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .forEach(dumps::add);
        }
        dumps.addAll(extraDumps);

        List<FixtureResult> results = new ArrayList<>();
        for (Path dump : dumps) {
            String name = dump.getFileName().toString().replaceFirst("\\.txt$", "");
            System.out.println("== " + name);
            Path fixOut = outDir.resolve(name);
            Files.createDirectories(fixOut);
            try {
                results.add(runFixture(jar, cwd, vault, dump, name, fixOut));
            } catch (Exception e) {
                System.out.println("    FAILED: " + e.getMessage());
                results.add(new FixtureResult(name, null, null, null, null, e.getMessage()));
            }
            Thread.sleep(3500); // stay under the 20 req/min captura rate limit
        }

        String matrix = renderMatrix(results);
        Files.writeString(outDir.resolve("matrix.md"), matrix, StandardCharsets.UTF_8);
        System.out.println();
        System.out.println(matrix);

        boolean bad = results.stream().anyMatch(r -> r.error() != null
                || r.comparison().verdict() == Verdict.DESVIO_INESPERADO
                || !r.roundTrip().ok());
        System.exit(bad ? 2 : 0);
    }

    static FixtureResult runFixture(Path jar, Path cwd, Path vault, Path dump, String name, Path fixOut)
            throws Exception {
        Path masked = fixOut.resolve(name + ".masked.txt");
        if (cli(jar, cwd, "mask", dump.toString(), "-o", masked.toString(),
                "--vault", vault.toString()) != 0) {
            throw new IOException("mask failed for " + name);
        }
        int verifyCode = cli(jar, cwd, "verify", dump.toString(), masked.toString(),
                "--vault", vault.toString());
        if (verifyCode != 0) {
            throw new IOException("verify failed for " + name + " (exit " + verifyCode + ")");
        }

        String origId = upload("e2e-parity " + name + " original", Files.readAllBytes(dump));
        Thread.sleep(3500);
        String maskId = upload("e2e-parity dump A", Files.readAllBytes(masked));

        String origDetail = pollUntilDone(origId, Duration.ofMinutes(3));
        String maskDetail = pollUntilDone(maskId, Duration.ofMinutes(3));
        Files.writeString(fixOut.resolve("original-detail.json"), origDetail, StandardCharsets.UTF_8);
        Files.writeString(fixOut.resolve("masked-detail.json"), maskDetail, StandardCharsets.UTF_8);

        String origExport = exportJson(origId);
        String maskExport = exportJson(maskId);
        Files.writeString(fixOut.resolve("original-export.json"), origExport, StandardCharsets.UTF_8);
        Path maskExportFile = fixOut.resolve("masked-export.json");
        Files.writeString(maskExportFile, maskExport, StandardCharsets.UTF_8);

        AnalysisFacts of = facts(origDetail);
        AnalysisFacts mf = facts(maskDetail);
        Comparison cmp = compare(of, mf);

        Path unmasked = fixOut.resolve("unmasked-export.json");
        if (cli(jar, cwd, "unmask", maskExportFile.toString(), "-o", unmasked.toString(),
                "--vault", vault.toString()) != 0) {
            throw new IOException("unmask failed for " + name);
        }
        RoundTrip rt = roundTrip(
                exportThreadNames(origExport),
                exportThreadNames(Files.readString(unmasked, StandardCharsets.UTF_8)));

        System.out.println("    original: health=" + of.healthScore() + " problems=" + summary(of));
        System.out.println("    masked:   health=" + mf.healthScore() + " problems=" + summary(mf));
        System.out.println("    verdict:  " + cmp.verdict()
                + (rt.ok() ? " | round-trip OK (" + rt.total() + " names)"
                           : " | ROUND-TRIP FAILED missing=" + rt.missing() + " unexpected=" + rt.unexpected()));
        cmp.notes().forEach(n -> System.out.println("      - " + n));
        return new FixtureResult(name, of, mf, cmp, rt, null);
    }

    static String summary(AnalysisFacts f) {
        if (f.problems().isEmpty()) return "(none)";
        Set<String> s = new LinkedHashSet<>();
        for (Problem p : f.problems()) {
            s.add(p.tipo() + ":" + p.severidade() + ":" + p.threadsAfetadas());
        }
        return String.join(", ", s);
    }

    static String renderMatrix(List<FixtureResult> results) {
        StringBuilder b = new StringBuilder();
        b.append("| Fixture | Health orig | Health masked | Problems orig | Problems masked | Verdict | Round-trip |\n");
        b.append("|---|---|---|---|---|---|---|\n");
        for (FixtureResult r : results) {
            if (r.error() != null) {
                b.append("| ").append(r.fixture()).append(" | - | - | - | - | ERRO: ")
                        .append(r.error()).append(" | - |\n");
                continue;
            }
            b.append("| ").append(r.fixture())
                    .append(" | ").append(r.original().healthScore())
                    .append(" | ").append(r.masked().healthScore())
                    .append(" | ").append(summary(r.original()))
                    .append(" | ").append(summary(r.masked()))
                    .append(" | ").append(r.comparison().verdict())
                    .append(" | ").append(r.roundTrip().ok()
                            ? "OK (" + r.roundTrip().total() + " names)"
                            : "FAILED missing=" + r.roundTrip().missing().size()
                              + " unexpected=" + r.roundTrip().unexpected().size())
                    .append(" |\n");
        }
        return b.toString();
    }

    // ------------------------------------------------------------------
    // Offline unit tests for the pure logic (no network involved)
    // ------------------------------------------------------------------

    static int failures;

    static void check(String name, boolean cond) {
        if (cond) {
            System.out.println("  ok  " + name);
        } else {
            System.out.println("  FAIL " + name);
            failures++;
        }
    }

    static int selfTest() {
        System.out.println("parity self-test (offline)");

        // JSON parser
        Object v = Json.parse("{\"a\": [1, 2.5, \"x\\n\", true, null], \"b\": {\"c\": -3}}");
        Map<String, Object> m = castMap(v);
        check("json object+array", ((List<?>) m.get("a")).size() == 5);
        check("json nested int", ((Number) castMap(m.get("b")).get("c")).intValue() == -3);
        check("json escape", ((List<?>) m.get("a")).get(2).equals("x\n"));

        // facts extraction
        String detail = """
                {"status":"CONCLUIDA","healthScore":55,"totalThreads":14,"formatoDetectado":"OPENJDK",
                 "problemasDetectados":{"problemas":[
                   {"tipo":"LOCK_CONTENTION","severidade":"WARNING","evidencia":{"quantidadeThreadsAfetadas":8}},
                   {"tipo":"THREAD_STARVATION","severidade":"CRITICAL","evidencia":{"quantidadeThreadsAfetadas":8}}]}}
                """;
        AnalysisFacts f = facts(detail);
        check("facts health", f.healthScore() == 55);
        check("facts problems", f.problems().size() == 2
                && f.problems().get(1).key().equals("THREAD_STARVATION/CRITICAL/8"));

        // compare: identical -> IGUAL
        AnalysisFacts a = new AnalysisFacts(55, 14, "OPENJDK", List.of(
                new Problem("LOCK_CONTENTION", "WARNING", 8),
                new Problem("THREAD_STARVATION", "CRITICAL", 8)));
        AnalysisFacts b = new AnalysisFacts(55, 14, "OPENJDK", List.of(
                new Problem("THREAD_STARVATION", "CRITICAL", 8),
                new Problem("LOCK_CONTENTION", "WARNING", 8)));
        check("identical (order-insensitive) -> IGUAL", compare(a, b).verdict() == Verdict.IGUAL);

        // rule (a): FILA_SEM_CONSUMO only in original -> expected
        AnalysisFacts c = new AnalysisFacts(50, 14, "OPENJDK", List.of(
                new Problem("LOCK_CONTENTION", "WARNING", 8),
                new Problem("FILA_SEM_CONSUMO", "WARNING", 3)));
        AnalysisFacts d = new AnalysisFacts(55, 14, "OPENJDK", List.of(
                new Problem("LOCK_CONTENTION", "WARNING", 8)));
        check("rule a -> DESVIO_ESPERADO", compare(c, d).verdict() == Verdict.DESVIO_ESPERADO);

        // rule (a) inverted: FILA_SEM_CONSUMO only in MASKED -> unexpected
        check("fila only in masked -> DESVIO_INESPERADO",
                compare(d, c).verdict() == Verdict.DESVIO_INESPERADO);

        // rule (b): scheduler differs in either direction -> expected
        AnalysisFacts e1 = new AnalysisFacts(60, 10, "HOTSPOT",
                List.of(new Problem("SCHEDULER_PROBLEMA", "WARNING", 1)));
        AnalysisFacts e2 = new AnalysisFacts(65, 10, "HOTSPOT", List.of());
        check("rule b orig-only -> DESVIO_ESPERADO", compare(e1, e2).verdict() == Verdict.DESVIO_ESPERADO);
        check("rule b masked-only -> DESVIO_ESPERADO", compare(e2, e1).verdict() == Verdict.DESVIO_ESPERADO);

        // new problem type appearing in masked -> unexpected
        AnalysisFacts g = new AnalysisFacts(55, 14, "OPENJDK", List.of(
                new Problem("LOCK_CONTENTION", "WARNING", 8),
                new Problem("THREAD_ORFA", "INFO", 1)));
        check("new type in masked -> DESVIO_INESPERADO", compare(a, g).verdict() == Verdict.DESVIO_INESPERADO);

        // same problems, different health -> unexpected
        AnalysisFacts h = new AnalysisFacts(54, 14, "OPENJDK", a.problems());
        check("health drift alone -> DESVIO_INESPERADO", compare(a, h).verdict() == Verdict.DESVIO_INESPERADO);

        // different affected-thread count -> unexpected
        AnalysisFacts k = new AnalysisFacts(55, 14, "OPENJDK", List.of(
                new Problem("LOCK_CONTENTION", "WARNING", 7),
                new Problem("THREAD_STARVATION", "CRITICAL", 8)));
        check("affected count drift -> DESVIO_INESPERADO", compare(a, k).verdict() == Verdict.DESVIO_INESPERADO);

        // thread total drift -> unexpected
        AnalysisFacts t = new AnalysisFacts(55, 13, "OPENJDK", a.problems());
        check("thread total drift -> DESVIO_INESPERADO", compare(a, t).verdict() == Verdict.DESVIO_INESPERADO);

        // round-trip
        check("round-trip equal", roundTrip(Set.of("a", "b"), Set.of("b", "a")).ok());
        check("round-trip missing", !roundTrip(Set.of("a", "b"), Set.of("a")).ok());
        check("round-trip unexpected", !roundTrip(Set.of("a"), Set.of("a", "t123xabc")).ok());

        // export thread-name extraction
        Set<String> names = exportThreadNames(
                "{\"threads\":[{\"nome\":\"w-1\"},{\"nome\":\"w-2\"}]}");
        check("export names", names.equals(Set.of("w-1", "w-2")));

        System.out.println(failures == 0 ? "ALL OK" : failures + " FAILURES");
        return failures == 0 ? 0 : 2;
    }
}

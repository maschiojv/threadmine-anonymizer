package dev.threadmine.anon.corpus;

import dev.threadmine.anon.allowlist.AllowlistMatcher;
import dev.threadmine.anon.core.HmacTokenEngine;
import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.format.openj9.JavacoreRewriter;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hard non-leak assertion for the javacore fixtures: every sensitive string
 * PLANTED in each fixture — cmdline secrets, hosts, env vars, classpath jars,
 * the 1TIFILENAME path, application classes from the stripped LK/CL sections,
 * pool/thread names — must be absent from the masked output, byte for byte.
 *
 * <p>The golden test proves the mask does what the expectation says; this one
 * proves the opposite direction: what must die, died. The lists are written
 * out by hand on purpose — a leak here is a compliance incident, not a diff
 * to rubber-stamp.</p>
 */
class JavacoreNoLeakTest {

    private static final Path FIXTURES = Path.of("corpus", "fixtures");

    // The 1CIJAVAVERSION TOKEN itself must die everywhere: its payload is
    // re-emitted under 1XMJAVAVERSION (SPEC 5-B.2 amendment), but a surviving
    // CI-family token is a verify finding. The payloads in these fixtures were
    // audited word by word — version/vendor/public GA build only, nothing
    // client-identifying — so no payload fragment belongs in the planted
    // lists; the sensitive-fragment path (path/hostname inside the version
    // line) is pinned by JavacoreRewriterTest.unsafeVersionFragmentsAreRedactedNotLeaked.
    private static final Map<String, List<String>> PLANTED = Map.of(
            "openj9-javacore-classic.txt", List.of(
                    // CI-family version token (payload survives, token must not)
                    "1CIJAVAVERSION",
                    // 1TIFILENAME local path
                    "D:\\acme", "javacore.20070314",
                    // 1CICMDLINE / 2CIUSERARG secrets and hosts
                    "Sw0rdf1sh!", "db01.pay.acme.example", "svc_pagamento", "payserver01",
                    "jdbc:oracle:thin", "acme.policy", "-Dacme.env=production",
                    // 1CISYSCP / -Djava.class.path jars
                    "acme-pay-core-2.4.1.jar", "acme-ledger-1.9.0.jar", "acme-antifraud-3.2.0.jar",
                    "vendor-scoring-5.1.jar", "cardswitch-client-7.0.2.jar", "oradriver-9.2.jar",
                    // thread and class names (XM tokenized, LK/CL stripped)
                    "QueueWorker", "acme.kernel.Default", "acme.kernel.System",
                    "ListenThread", "CoreHealthMonitor", "PayServer", "LedgerCache",
                    "PaymentRouter", "CardSwitchClient", "AcmeServerSocket",
                    "HealthBoard", "ScoreMatrix", "AcmeModuleClassLoader",
                    "com.acme", "com/acme"),
            "openj9-javacore-moderno.txt", List.of(
                    // CI-family version token (dump already has 1XMJAVAVERSION: no re-emission)
                    "1CIJAVAVERSION",
                    // 1TIFILENAME and deploy paths
                    "/opt/acme", "javacore.20260210",
                    // 1CICMDLINE / 2CIENVVAR secrets
                    "Hunter2!", "db01.pay.acme.example", "acme-payments",
                    "ACME_DB_PASSWORD", "acme-payments-7d9f4c-x2lqz",
                    "acme-payments-svc-4.12.0.jar", "-Dacme.tenant",
                    // thread names (incl. the route thread) and classes
                    "pgto-worker", "tenant-acme", "invoice=99887766", "/api/payments",
                    "WalletService", "PaymentWorker", "PaymentQueue",
                    "CardSwitchClient", "PaymentSyncHandler", "Application.java",
                    "com/acme"),
            "openj9-javacore-deadlock.txt", List.of(
                    "1CIJAVAVERSION",
                    "/opt/acme", "javacore.20260211", "Hunter2!", "-Dacme.tenant",
                    "acme-payments-svc-4.12.0.jar",
                    "pgto-worker", "WalletService", "LedgerBook", "PaymentWorker",
                    "PaymentQueue", "com/acme",
                    // the LOCKS section dies whole, deadlock announcement included
                    "1LKDEADLOCK", "Deadlock detected", "LKDEADLOCKTHR"));

    @TempDir
    Path tempDir;

    static List<String> fixtures() {
        return List.copyOf(PLANTED.keySet());
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void noPlantedSensitiveStringSurvivesMasking(String name) throws IOException {
        String text = Files.readString(FIXTURES.resolve(name), StandardCharsets.UTF_8);
        var engine = new HmacTokenEngine(Vault.create(tempDir.resolve(name + "-vault.json")));
        String masked = new JavacoreRewriter(engine, AllowlistMatcher.fromClasspath()).mask(text).output();

        for (String planted : PLANTED.get(name)) {
            assertTrue(text.contains(planted),
                    "planted string missing from the fixture itself (list out of date): " + planted);
            assertFalse(masked.contains(planted),
                    "sensitive string survived masking: \"" + planted + "\" in " + name);
        }
    }
}

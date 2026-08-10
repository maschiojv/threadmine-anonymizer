package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.TokenEngine;
import dev.threadmine.anon.verify.ComplianceVerifier;
import dev.threadmine.anon.verify.VerifyReport;

/**
 * The compliance check {@code mask} runs on its own output before letting it
 * reach the disk.
 *
 * <p>It is the very same {@link ComplianceVerifier} the standalone {@code
 * verify} command runs, and that is the point: the check stays an adversarial
 * second pass over the masked text — it re-derives every identifier from the
 * file instead of trusting what the rewriter believes it did — so running it
 * inside {@code mask} buys convenience without softening the guarantee.</p>
 */
@FunctionalInterface
interface ComplianceGate {

    VerifyReport check(String original, String masked, TokenEngine engine);

    /** The shipped gate: the real verifier, judging against the shipped allowlist. */
    static ComplianceGate standard() {
        return new ComplianceVerifier(AllowlistBridge.fromClasspath())::verify;
    }
}

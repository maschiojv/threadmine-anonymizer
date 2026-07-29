package dev.threadmine.anon.unmask;

import java.util.List;

/**
 * Outcome of one unmask pass.
 *
 * @param replacedOccurrences    how many token occurrences were restored
 * @param distinctTokensReplaced how many different tokens those occurrences covered
 * @param unresolvedTokens       tokens found in the text but unknown to this vault,
 *                               in order of first appearance, exactly as they appear
 * @param unresolvedOccurrences  how many occurrences those unknown tokens had
 */
public record UnmaskResult(String text,
                           int replacedOccurrences,
                           int distinctTokensReplaced,
                           List<String> unresolvedTokens,
                           int unresolvedOccurrences) {

    public UnmaskResult {
        unresolvedTokens = List.copyOf(unresolvedTokens);
    }

    /**
     * True when the text carried tokens this vault cannot reverse — normally
     * the wrong vault, or output produced before the vault was recreated.
     */
    public boolean hasUnresolvedTokens() {
        return !unresolvedTokens.isEmpty();
    }
}

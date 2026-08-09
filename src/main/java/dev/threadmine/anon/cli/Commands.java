package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.core.VaultException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

/** Helpers shared by the tm-anon commands: vault location and vault opening. */
final class Commands {

    /** Vault file used when {@code --vault} is absent (SPEC §2). */
    static final String DEFAULT_VAULT_FILE = "tm-anon-vault.json";

    static final String VAULT_OPTION = "--vault";
    static final Set<String> VAULT_ONLY = Set.of(VAULT_OPTION);
    /** {@code init --encrypt}: create the vault sealed with a passphrase (SPEC §2). */
    static final String ENCRYPT_FLAG = "--encrypt";

    private Commands() {
    }

    /** Resolves {@code --vault} against the working directory; relative paths stay relative to it. */
    static Path vaultPath(Args args, Path workingDir) {
        return workingDir.resolve(args.value(VAULT_OPTION).orElse(DEFAULT_VAULT_FILE));
    }

    /**
     * Opens an existing vault, turning "file is simply not there" into an
     * actionable message instead of a bare I/O failure.
     */
    static Vault openVault(Path vaultFile) {
        return openVault(vaultFile, PassphraseSource.standard());
    }

    /**
     * Same, asking {@code passphrases} for the passphrase when the vault turns
     * out to be encrypted. A plaintext vault never triggers a prompt, so the
     * common case stays a single command with no interaction.
     */
    static Vault openVault(Path vaultFile, PassphraseSource passphrases) {
        if (!Files.exists(vaultFile)) {
            throw new VaultException("vault not found: " + vaultFile.toAbsolutePath()
                    + " - run 'tm-anon init' first, or point --vault at an existing vault");
        }
        if (!Vault.isEncrypted(vaultFile)) {
            return Vault.load(vaultFile);
        }
        char[] passphrase = passphrases.existing();
        if (passphrase == null) {
            throw new VaultException("vault is encrypted and no passphrase is available: "
                    + vaultFile.toAbsolutePath()
                    + " - set " + PassphraseSource.ENV_VAR + " or run this from a terminal");
        }
        return Vault.load(vaultFile, passphrase);
    }
}

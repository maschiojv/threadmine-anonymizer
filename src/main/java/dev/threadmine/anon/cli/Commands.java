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
        if (!Files.exists(vaultFile)) {
            throw new VaultException("vault not found: " + vaultFile.toAbsolutePath()
                    + " - run 'tm-anon init' first, or point --vault at an existing vault");
        }
        return Vault.load(vaultFile);
    }
}

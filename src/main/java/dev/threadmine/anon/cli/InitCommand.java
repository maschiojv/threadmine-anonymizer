package dev.threadmine.anon.cli;

import dev.threadmine.anon.core.Vault;
import dev.threadmine.anon.core.VaultException;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;

/**
 * {@code tm-anon init [--vault <path>]} — creates a fresh vault.
 *
 * <p>The vault is the only thing that can turn tokens back into real names, so
 * this command has two jobs beyond writing the file: tell the user to back it
 * up (losing it makes every past masked dump permanently unreadable) and stop
 * it from being committed by accident.</p>
 */
final class InitCommand {

    private InitCommand() {
    }

    static int execute(String[] argv, Path workingDir, PrintStream out, PrintStream err) {
        Args args;
        try {
            args = Args.parse(argv, Commands.VAULT_ONLY, Set.of());
        } catch (Args.UsageException e) {
            err.println("init: " + e.getMessage());
            return ExitCodes.USAGE;
        }
        if (!args.positionals().isEmpty()) {
            err.println("init: unexpected argument: " + args.positionals().get(0));
            return ExitCodes.USAGE;
        }

        Path vaultFile = Commands.vaultPath(args, workingDir);
        try {
            Path parent = vaultFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            try (Vault ignored = Vault.create(vaultFile)) {
                // create() already persisted the fresh key; close() is a no-op here.
            }
        } catch (VaultException e) {
            err.println("init: " + e.getMessage());
            return ExitCodes.VAULT_ERROR;
        } catch (IOException e) {
            err.println("init: cannot create directory for " + vaultFile.toAbsolutePath() + ": " + e.getMessage());
            return ExitCodes.VAULT_ERROR;
        }

        out.println("Created vault: " + vaultFile.toAbsolutePath());
        gitignore(vaultFile, workingDir, out, err);
        out.println();
        out.println("Back this file up. It holds the HMAC key and the token dictionary:");
        out.println("  - lose it and you can never unmask an already masked dump;");
        out.println("  - share it and anyone can unmask those dumps.");
        out.println("Never commit it, never upload it, never attach it to a ticket.");
        return ExitCodes.OK;
    }

    /**
     * Adds the vault to {@code .gitignore} when the working directory is a git
     * repository and the vault lives inside it. A repository is detected by a
     * {@code .git} entry, which is a directory in a normal clone and a file in
     * a worktree or submodule.
     */
    private static void gitignore(Path vaultFile, Path workingDir, PrintStream out, PrintStream err) {
        if (!Files.exists(workingDir.resolve(".git"))) {
            return;
        }
        String entry = relativeEntry(vaultFile, workingDir);
        if (entry == null) {
            return;
        }
        Path gitignore = workingDir.resolve(".gitignore");
        try {
            if (Files.exists(gitignore)) {
                List<String> lines = Files.readAllLines(gitignore, StandardCharsets.UTF_8);
                for (String line : lines) {
                    String trimmed = line.strip();
                    if (trimmed.equals(entry) || trimmed.equals("/" + entry)) {
                        return;
                    }
                }
                String current = Files.readString(gitignore, StandardCharsets.UTF_8);
                String prefix = current.isEmpty() || current.endsWith("\n") ? "" : "\n";
                Files.writeString(gitignore, prefix + entry + "\n", StandardCharsets.UTF_8,
                        StandardOpenOption.APPEND);
            } else {
                Files.writeString(gitignore, entry + "\n", StandardCharsets.UTF_8);
            }
            out.println("Added to .gitignore: " + entry);
        } catch (IOException e) {
            err.println("init: warning — could not update .gitignore (" + e.getMessage()
                    + "); add '" + entry + "' by hand");
        }
    }

    /** Repository-relative, slash-separated path, or {@code null} when the vault is outside the repo. */
    private static String relativeEntry(Path vaultFile, Path workingDir) {
        Path root = workingDir.toAbsolutePath().normalize();
        Path vault = vaultFile.toAbsolutePath().normalize();
        if (!vault.startsWith(root)) {
            return null;
        }
        return root.relativize(vault).toString().replace('\\', '/');
    }
}

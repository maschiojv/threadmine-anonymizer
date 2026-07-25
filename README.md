# tm-anon

Local, offline anonymizer for JVM thread dumps.

`tm-anon` masks application identifiers (packages, classes, methods, thread
names) in a thread dump **before** it leaves your machine, so you can send the
dump to an analysis service — such as [ThreadMine](https://threadmine.dev) —
without disclosing internal names. The reverse mapping lives in a local vault
file that never leaves your machine, so you (and only you) can restore the
original names in any analysis output.

## Design principles

- **Zero network code.** The jar contains no HTTP client, no `java.net` usage,
  no network dependency — direct or transitive. This is enforced by an
  architecture test that scans sources, bytecode and the Maven dependency
  list. You can audit in minutes that this tool *cannot* exfiltrate anything.
- **Deterministic tokens.** Tokens are derived with HMAC-SHA256 from a random
  256-bit key stored in your local vault. Same vault, same name, same token —
  across dumps, forever. Cross-dump analyses (diff, timeline) keep working.
- **Keyed, not just hashed.** Without the vault key, a token cannot be
  reversed *or even guessed at* by dictionary attack (Kerckhoffs' principle:
  the code is public, the key is yours).
- **Fail-closed.** Anything the rewriter does not recognize is redacted, never
  passed through verbatim.

## Status

Early development. Current scope: token engine and local vault (core).
Masking, unmasking and verification commands are under construction.

## Build

```
./mvnw package
```

Produces a single self-contained jar (`target/tm-anon-<version>.jar`).

## License

[MIT](LICENSE)

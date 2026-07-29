# GraalVM native-image metadata

`tm-anon` uses no reflection, no dynamic proxies, no JNI and no service
loaders, so this directory holds the minimum a native build needs: the
allowlist JSON must stay in the image.

`AllowlistMatcher.fromClasspath()` reads `/allowlist-v1.json` through
`getResourceAsStream`, and `native-image` does not embed classpath resources
unless they are declared. That single entry is `resource-config.json`.

It is the only classpath resource the CLI loads at runtime. If a future change
adds reflection or another resource, the native binaries will fail the release
smoke test (mask + verify on a real fixture) before they are published — that
smoke test exists for exactly this reason.

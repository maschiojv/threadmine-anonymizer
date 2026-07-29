# Security policy

## Scope

The security property this project claims is narrow and testable: **a dump
masked by `tm-anon` contains no application identifier, and nothing in the jar
can send anything anywhere.**

The full reasoning, including what a masked dump still reveals and what this
tool deliberately does not protect against, is in [THREAT_MODEL.md](THREAT_MODEL.md).

## What counts as a vulnerability here

- An application package, class, method or thread name surviving `mask` on a
  supported dump format (`verify` should have caught it; if it did not, that is
  two bugs).
- A dialect being partially masked instead of refused. Unsupported input must
  exit `2`, never produce a half-masked file.
- Any network capability in the shipped jar. `NoNetworkArchitectureTest` is
  supposed to make this impossible; a way around it is a finding.
- A token that is reversible without the vault, or a weakness in how the vault
  key is generated or stored.

Known and documented, so not vulnerabilities: the vault has no passphrase
encryption yet, masked dumps from one vault are linkable to each other, and
structural metadata (framework stack, pool shapes, JVM version) stays visible.

## Reporting

Use GitHub's **Report a vulnerability** button on the Security tab of this
repository (private advisory), or email `founder@threadmine.dev`.

**Never attach a real thread dump.** Reduce the case to a synthetic fixture in
the style of `corpus/fixtures/` (fictional `com.acme.*` namespace). If a
reproduction genuinely cannot be reduced, describe the shape of the input
instead and we will build the fixture together.

Expect a first reply within a few working days. This is a small project; there
is no bounty program, and there is no bureaucracy either.

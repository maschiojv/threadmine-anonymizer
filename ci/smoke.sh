#!/usr/bin/env bash
#
# End-to-end smoke test of a built tm-anon, exercised through whatever launcher
# is passed in: a jar ("java -jar target/tm-anon.jar") or a native binary
# ("./tm-anon"). It runs against a real corpus fixture and checks the promises
# that matter, not just the exit codes:
#
#   - the application package disappears from the masked file;
#   - the allowlisted pool name survives (that is what keeps detection working);
#   - mask gates its own output and says PASS;
#   - verify says PASS on its own too;
#   - unmask brings the real name back;
#   - an input that is not a thread dump is refused with exit 2 (fail-closed).
#
# Usage: ci/smoke.sh <launcher...>
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: ci/smoke.sh <launcher...>   e.g. ci/smoke.sh java -jar target/tm-anon.jar" >&2
  exit 64
fi

repo_root=$(cd "$(dirname "$0")/.." && pwd)
fixture="$repo_root/corpus/fixtures/jstack-jdk17-synchronizers.txt"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

launcher=("$@")
run() { "${launcher[@]}" "$@"; }

cp "$fixture" "$work/dump.txt"

echo "--- init"
run init --vault "$work/vault.json"

echo "--- mask"
run mask "$work/dump.txt" -o "$work/masked.txt" --vault "$work/vault.json" | tee "$work/mask.txt"
grep -q '^verify: PASS' "$work/mask.txt" \
  || { echo "FAIL: mask did not run its own compliance gate"; exit 1; }

echo "--- verify"
run verify "$work/dump.txt" "$work/masked.txt" --vault "$work/vault.json" | tee "$work/verify.txt"
grep -q '^PASS' "$work/verify.txt" || { echo "FAIL: verify did not pass"; exit 1; }

echo "--- masked content"
if grep -q 'com\.acme' "$work/masked.txt"; then
  echo "FAIL: application package survived masking"
  exit 1
fi
grep -q 'http-nio-8080-exec-1' "$work/masked.txt" \
  || { echo "FAIL: allowlisted thread name was tokenized"; exit 1; }
head -n 1 "$work/masked.txt" | grep -q '^# tm-anon v1' \
  || { echo "FAIL: missing '# tm-anon v1' marker"; exit 1; }

echo "--- unmask round-trip"
run unmask "$work/masked.txt" -o "$work/plain.txt" --vault "$work/vault.json"
grep -q 'com\.acme\.payment\.LedgerService' "$work/plain.txt" \
  || { echo "FAIL: unmask did not restore the original class name"; exit 1; }

echo "--- fail-closed on a non-dump"
printf 'this is not a thread dump\n' > "$work/junk.txt"
set +e
run mask "$work/junk.txt" --vault "$work/vault.json"
code=$?
set -e
if [ "$code" -ne 2 ]; then
  echo "FAIL: expected exit 2 for unsupported input, got $code"
  exit 1
fi

echo "smoke test OK"

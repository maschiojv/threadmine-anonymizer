# Changelog

## 0.4.1 (2026-10-20)

### Changed
- **Allowlist v2** (`allowlist/allowlist-v2.json`, replaces `allowlist-v1.json`). Virtual-thread
  markers now come from real JDK 21-25 dumps (`generatedFrom.files`), not synthetic fixtures.
  - Removed `<pinned: synchronized>` and `<virtual thread is mounted on carrier thread "...">`:
    no JDK prints them. A line like that is now treated as unknown and redacted (fail-closed).
  - Added `Mounted virtual thread #N` (JDK 24+ jstack; before, `mask` redacted every such line),
    the `java.lang.VirtualThread.parkOnCarrierThread` pin frame, and the `#N "" virtual [STATE]`
    and carrier-header patterns to the structural markers.
  - Added JDK-internal thread names that were being tokenized: `VirtualThread-unparker` (21-23),
    `Read-Updater` / `Write-Updater` (21) and `ForkJoinPool-N-delayScheduler` (25).
- `verify` anchors: `Mounted virtual thread #` added, the two false markers dropped.

### Added
- Corpus: 11 real JDK 21-25 dumps (`dump_to_file` text for 21-25, jstack for 21-25, one
  `Thread.print`) with expectations. They mask with 0 redacted lines and pass `verify`.

# Architecture

## Layers
- `core`: image readers and TSK image adapter.
- `domain`: forensic entities and extraction/catalog records.
- `forensics`: partition enumeration, filesystem access, generic browsing, extraction.
- `workers`: threaded workers for open/scan/list/extract.
- `utils`: logging, hashing, serialization, path handling, timestamp policy.
- `gui`: Qt Widgets presentation and orchestration.
- `cli`: headless command surface for inspect/list/extract/catalog using `fie_core` only (no Widgets dependency).

## Real forensic path (RAW/DD)
1. `RawImageReader` opens image read-only.
2. `TskImageHandleAdapter` opens a `TSK_IMG_INFO`.
3. `VolumeEnumerator` parses partition table via `tsk_vs_open`.
4. `FileSystemHandle` opens partition filesystem via `tsk_fs_open_img`.
5. `FileSystemBrowser` lists directory entries from `tsk_fs_dir_open` + `tsk_fs_dir_get`, then conditionally enriches NTFS-specific metadata.
6. `ExtractionService` recursively expands directories and streams file data in chunks via `tsk_fs_file_read`.

## E01 interoperability status
- `EwfImageReader` is real libewf-backed (`open/size/read`) including segmented-set discovery.
- `TskImageHandleAdapter` explicitly separates two backends:
  - reader-bridge backend (default operational path via TSK external-image callbacks)
  - path-based backend (compatibility mode only; attempted only when `allowPathFallback=true` and bridge open fails)
- `TskReaderBridge` now owns a production callback bridge state (`shared_ptr<IImageReader>` + `ReadCache`) and handles random reads, bounds-safe short reads, and cleanup through TSK close callbacks.
- Result semantics are explicit: reader-backed success => `ReaderBridge` backend with no warning; reader-backed failure + path success => warning + `PathBased`; both fail => hard error with combined diagnostics.
- A narrow `TskExternalImageApi` wrapper isolates version-sensitive TSK external-image open/error calls from the bridge logic.

## Timestamp handling
- Generic filesystem timestamps come from `TSK_FS_META`.
- NTFS SI/FN timestamps are retained as optional enrichment fields and only populated when NTFS capabilities are detected.
- ADS and SI/FN are shown in UI/catalog as NTFS-specific fields.
- Host timestamp application is optional and recorded per extraction item.

## Warning/error separation
- TSK adapter fallback warnings are surfaced as warnings (not hard errors) through worker signals.

## Performance and responsiveness model
- `core::ReadCache` provides fixed-size block caching for `IImageReader`-backed random reads and is reusable by bridge/callback-style readers to avoid redundant backend reads.
- The TSK reader bridge uses `ReadCache` to reduce repeated backend reads during filesystem/metadata traversal, keeping the callback path responsive for EWF-backed random access.
- Long-running worker flows are cooperative and cancellable via `forensics::CancellationToken` (`requestCancel` slot on open/scan/list/extract workers).
- Extraction progress is reported as structured `ProgressInfo` with per-file and aggregate byte counters; UI status text is updated from worker progress signals.
- Extraction remains read-only; short reads, warnings, and error statuses are preserved and surfaced exactly as before.
- The current pass intentionally avoids speculative indexing/background scanning and focuses on deterministic throughput + UI responsiveness.


## Artifact Explorer MVP (Phase 1)
- `forensics::ArtifactDiscoveryService` is a domain/service layer that resolves Windows artifact paths from discovered `/Users/*` profiles plus system-wide locations.
- The service consumes a directory-list callback so path resolution logic is testable without widget dependencies.
- Output is `domain::ArtifactRecord` (category, artifact name, profile, logical path, status, size/timestamp, partition/filesystem context, notes).
- `workers::ArtifactScanWorker` wires GUI async execution to the service and returns both artifact rows and partial-failure warnings for analyst visibility.
- Missing resolver targets are represented as `ArtifactRecord.status="Missing"` (not warnings); warnings are reserved for traversal/listing failures and cancellation/error conditions.
- `gui::ArtifactTableModel` and the MainWindow `Artifacts` tab provide scan/extract/copy/jump actions while reusing existing extraction/catalog plumbing.
- Artifact scan entry is softly gated by a lightweight heuristic (partition FS type + `/Windows` root presence probe) to avoid noisy scans on clearly non-Windows targets; this is intentionally best-effort, not authoritative OS detection.

## File browser upgrade (Phase 2 incremental)
- `FileEntryTableModel` exposes additional forensic triage columns (logical path + allocated state) while preserving existing timestamp/ADS metadata surfaces.
- `FileEntryFilterProxyModel` now supports allocated-only, extension, and path-content filters in addition to existing deleted/type/ADS/name filters.
- File table context menu adds examiner-centric actions: extract, copy logical path, jump parent, export row metadata, and open related artifact context.
- Metadata shown in the browser remains sourced from existing `forensics::FileSystemBrowser` (TSK directory/meta fields + NTFS-specific enrichment where available).

## GUI workspace refinements
- Evidence summary fields (image path/format/size, selected partition, filesystem type) are pinned at the top of the main workspace for analyst context retention.
- File listing uses model/view (`FileEntryTableModel` + `FileEntryFilterProxyModel`) to keep filtering/search responsive for large directories.
- Analyst-facing filters support name contains, deleted-only, files/directories type selection, and ADS-only scope.
- Selection details include metadata summary plus safe bounded preview (hex + sanitized text) of first bytes via read-only TSK file reads.
- Extraction UX uses a dock with live progress, per-file status table updates, and final summary counts (success/warning/error/skipped).


## Extraction outcome taxonomy
- `primaryOutcome` captures the deterministic extraction outcome (`success*`, `short_read`, `read_failed`, `write_failed`, etc.).
- `status` is derived from `primaryOutcome` + warning/error presence and remains stable for reporting (`success_with_warning` for successful outcomes with warnings; non-success outcomes remain unchanged).
- Warnings and errors are separated:
  - warnings: non-fatal forensic context (`source_entry_deleted`, timestamp-apply failures, compatibility fallback warnings)
  - errors: hard-fail conditions (open/read/write failures).
- Metadata serializers persist `primary_outcome`, `status`, `warning`, `error`, `bytes_written`, and host timestamp fields without lossy transformation.

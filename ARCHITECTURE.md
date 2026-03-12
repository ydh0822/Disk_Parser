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

## Declared support scope boundaries
- Image format messaging is intentionally scoped to RAW/DD and E01/EWF for this milestone.
- Filesystem messaging is intentionally scoped to NTFS, FAT32, exFAT, EXT3, and EXT4 as primary support targets.
- ReFS and XFS are explicitly treated as not-currently-supported targets in user messaging.
- Directory browsing may still succeed through generic TSK flows on additional filesystems; when that occurs, worker/UI result messaging must remain explicit that support is unconfirmed.

## Timestamp handling
- Generic filesystem timestamps come from `TSK_FS_META`.
- NTFS SI/FN timestamps are retained as optional enrichment fields and only populated when NTFS capabilities are detected.
- ADS and SI/FN are shown in UI/catalog as NTFS-specific fields.
- Host timestamp application is optional and recorded per extraction item.

## End-to-end operation result semantics
- All worker-facing forensic pipeline stages now emit `domain::ForensicOperationResult` with the same shape:
  - `state`: `Success`, `SuccessWithWarning`, or `Failure`
  - `backend`: `ReaderBridge`, `PathFallback`, `Unknown`, or `NotApplicable`
  - `diagnostic`: `reason` (stable machine token), `userMessage` (UI-facing text), `detail` (internal context)
- This applies consistently across image open, partition enumeration, filesystem open/list flows, artifact scan, and extraction worker completion.
- Stage naming is split intentionally: image-reader stage uses `image_reader_*` reason tokens, while TSK adapter open uses `tsk_image_open_*` reason tokens to avoid conflating reader open with TSK backend open.
- Cancellation policy is explicit and deterministic across workers: cancellation always emits `Failure` with reason token `cancelled` and does not rely on downstream error-string matching.
- Partial-payload policy on cancellation is **discard**: partition lists, directory entries, artifact rows, and extraction rows are suppressed when cancellation is observed after a long-running call, preventing cancelled operations from being misread as successful partial runs.
- Backend semantics on open failure are explicit: `ReaderBridge` when fallback is disabled (primary-path failure), `Unknown` when fallback is enabled and open fails (bridge/fallback failure path cannot truthfully be reduced to one backend), and `PathFallback`/`ReaderBridge` only once an image is actually open.
- UI orchestration (`MainWindow`) consumes this structured result instead of ambiguous `bool + QString` combinations and logs backend + reason for forensic traceability.

## Warning/error separation
- TSK adapter fallback warnings are surfaced as warnings (not hard errors), and fallback backend usage is explicitly tagged as `PathFallback` in operation results.
- Fallback success is no longer semantically identical to primary success at orchestration boundaries.
- `diagnostic.detail` is diagnostic-only free text (log/analyst context), not a structured warnings protocol; callers must not parse it.

## Performance and responsiveness model
- `core::ReadCache` provides fixed-size block caching for `IImageReader`-backed random reads and is reusable by bridge/callback-style readers to avoid redundant backend reads.
- The TSK reader bridge uses `ReadCache` to reduce repeated backend reads during filesystem/metadata traversal, keeping the callback path responsive for EWF-backed random access.
- Long-running worker flows are cooperative and cancellable via `forensics::CancellationToken` (`requestCancel` slot on open/scan/list/extract workers).
- Extraction progress is reported as structured `ProgressInfo` with per-file and aggregate byte counters; UI status text is updated from worker progress signals.
- Extraction remains read-only; short reads, warnings, and error statuses are preserved and surfaced exactly as before.
- Extraction cancellation policy: worker payload/catalog updates are suppressed on cancellation; GUI marks in-flight rows as cancelled. Partially written files may still exist on disk when cancellation occurs mid-stream, and this is reported as cancellation context rather than successful extraction rows.
- Worker cancellation paths and failures use deterministic `Failure` result states with explicit reason tokens (for example `cancelled`, `filesystem_open_failed`, `directory_list_failed`, `extraction_failed`).
- The current pass intentionally avoids speculative indexing/background scanning and focuses on deterministic throughput + UI responsiveness.


## Artifact Explorer MVP (Phase 1)
- `forensics::ArtifactDiscoveryService` is a domain/service layer that resolves Windows artifact paths from discovered `/Users/*` profiles plus system-wide locations.
- The service consumes a directory-list callback so path resolution logic is testable without widget dependencies.
- Output is `domain::ArtifactRecord` (category, artifact name, profile, logical path, status, size/timestamp, partition/filesystem context, notes).
- `workers::ArtifactScanWorker` wires GUI async execution to the service and returns artifact rows plus a single structured operation result; scan warnings are carried in `ForensicOperationResult.diagnostic.detail` when `state=SuccessWithWarning`.
- Missing resolver targets are represented as `ArtifactRecord.status="Missing"` (not warnings); warnings are reserved for traversal/listing failures and cancellation/error conditions.
- `gui::ArtifactTableModel` and the MainWindow `Artifacts` tab provide scan/extract/copy/jump actions while reusing existing extraction/catalog plumbing.
- Artifact scan entry is softly gated by a lightweight heuristic (partition FS type + `/Windows` root presence probe) to avoid noisy scans on clearly non-Windows targets; this is intentionally best-effort, not authoritative OS detection.

## File browser upgrade (Phase 2 incremental)
- `FileEntryTableModel` exposes additional forensic triage columns (logical path + allocated state) while preserving existing timestamp/ADS metadata surfaces.
- `FileEntryFilterProxyModel` now supports allocated-only, extension, path-content, and row-status filters in addition to existing deleted/type/ADS/name filters.
- File table context menu adds examiner-centric actions: extract, copy logical path, jump parent, export row metadata, and open related artifact context; correlation is intentionally path-only (exact/ancestor/descendant), exposes reason labels in UI metadata/status, and keeps deterministic ranking (exact > ancestor > descendant) for analyst auditability.
- Metadata shown in the browser remains sourced from existing `forensics::FileSystemBrowser` (TSK directory/meta fields + NTFS-specific enrichment where available).

## GUI workspace refinements
- Evidence summary fields (image path/format/size, selected partition, current path, filesystem type) are pinned at the top of the main workspace for analyst context retention.
- File listing uses model/view (`FileEntryTableModel` + `FileEntryFilterProxyModel`) plus explicit column-visibility profiles (triage, NTFS detail, extraction/status) with deterministic order/sort defaults to keep filtering/search responsive for large directories while preserving dense metadata access.
- Analyst-facing filters are grouped as a compact triage control surface (name/extension/type/path/status + deleted/allocated/ADS toggles) to keep density while reducing form clutter.
- Selection details include a dense, sectioned metadata summary (allocated/deleted state, inode/file-id, generic MACB timestamps, NTFS-specific SI/FN/ADS when present, and current row status) plus safe bounded read-only preview (offset hexdump + sanitized text + lightweight signature hint + truncation context) of first bytes via TSK file reads.
- Extraction UX uses a dock with live progress, per-file status table updates, and final summary counts (success/warning/error/skipped).


## Extraction outcome taxonomy
- `primaryOutcome` captures the deterministic extraction outcome (`success*`, `short_read`, `read_failed`, `write_failed`, etc.).
- `status` is derived from `primaryOutcome` + warning/error presence and remains stable for reporting (`success_with_warning` for successful outcomes with warnings; non-success outcomes remain unchanged).
- Warnings and errors are separated:
  - warnings: non-fatal forensic context (`source_entry_deleted`, timestamp-apply failures, compatibility fallback warnings)
  - errors: hard-fail conditions (open/read/write failures).
- Metadata serializers persist `primary_outcome`, `status`, `warning`, `error`, `bytes_written`, and host timestamp fields without lossy transformation.

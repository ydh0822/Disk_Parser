# Architecture

## Layers
- `core`: image readers and TSK image adapter.
- `domain`: forensic entities and extraction/catalog records.
- `forensics`: partition enumeration, filesystem access, generic browsing, extraction.
- `workers`: threaded workers for open/scan/list/extract.
- `utils`: logging, hashing, serialization, path handling, timestamp policy.
- `gui`: Qt Widgets presentation and orchestration.

## Real forensic path (RAW/DD)
1. `RawImageReader` opens image read-only.
2. `TskImageHandleAdapter` opens a `TSK_IMG_INFO`.
3. `VolumeEnumerator` parses partition table via `tsk_vs_open`.
4. `FileSystemHandle` opens partition filesystem via `tsk_fs_open_img`.
5. `FileSystemBrowser` lists directory entries from `tsk_fs_dir_open` + `tsk_fs_dir_get`, then conditionally enriches NTFS-specific metadata.
6. `ExtractionService` recursively expands directories and streams file data in chunks via `tsk_fs_file_read`.

## E01 interoperability status
- `EwfImageReader` is real libewf-backed (`open/size/read`) including segmented-set discovery.
- `TskImageHandleAdapter` now explicitly separates two backends:
  - reader-bridge backend (planned callback-backed `IImageReader` integration)
  - path-based backend (current operational fallback)
- This makes the E01+TSK gap explicit without pretending full callback bridge completion yet.

## Timestamp handling
- Generic filesystem timestamps come from `TSK_FS_META`.
- NTFS SI/FN timestamps are retained as optional enrichment fields and only populated when NTFS capabilities are detected.
- ADS and SI/FN are shown in UI/catalog as NTFS-specific fields.
- Host timestamp application is optional and recorded per extraction item.

## Warning/error separation
- TSK adapter fallback warnings are surfaced as warnings (not hard errors) through worker signals.

## Performance and responsiveness model
- `core::ReadCache` provides fixed-size block caching for `IImageReader`-backed random reads and is reusable by bridge/callback-style readers to avoid redundant backend reads.
- Long-running worker flows are cooperative and cancellable via `forensics::CancellationToken` (`requestCancel` slot on open/scan/list/extract workers).
- Extraction progress is reported as structured `ProgressInfo` with per-file and aggregate byte counters; UI status text is updated from worker progress signals.
- Extraction remains read-only; short reads, warnings, and error statuses are preserved and surfaced exactly as before.
- The current pass intentionally avoids speculative indexing/background scanning and focuses on deterministic throughput + UI responsiveness.


## GUI workspace refinements
- Evidence summary fields (image path/format/size, selected partition, filesystem type) are pinned at the top of the main workspace for analyst context retention.
- File listing uses model/view (`FileEntryTableModel` + `FileEntryFilterProxyModel`) to keep filtering/search responsive for large directories.
- Analyst-facing filters support name contains, deleted-only, files/directories type selection, and ADS-only scope.
- Selection details include metadata summary plus safe bounded preview (hex + sanitized text) of first bytes via read-only TSK file reads.
- Extraction UX uses a dock with live progress, per-file status table updates, and final summary counts (success/warning/error/skipped).

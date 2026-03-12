# Forensic Image Extractor

Forensic Image Extractor provides both a Qt 6 Widgets desktop application and a headless CLI for read-only forensic image analysis and extraction.

## Current implementation focus
- RAW/DD image open via `RawImageReader`.
- E01/EWF image open via `EwfImageReader` using libewf with deterministic segment discovery across E##/EX##/S## variants (including non-fatal gap warnings).
- Real TSK-backed partition enumeration.
- Real filesystem open at selected partition offset.
- Real generic filesystem directory listing via TSK directory APIs, with optional NTFS metadata enrichment when applicable.
- Recursive subtree extraction for selected directories.
- Chunked streaming extraction (4 MiB blocks), incremental SHA-256 (optional MD5), and zero-byte handling with explicit status taxonomy (e.g., `short_read`, `read_failed`, `write_failed`, `success_versioned`).
- Overwrite policies: `SkipExisting`, `Overwrite`, `VersionedCopy`.
- GUI directory navigation through partition/directory tree nodes with load-state caching.
- Evidence summary header, interactive table filters (name/deleted/type/ADS), safe first-bytes preview, and extraction progress workspace dock.

- Artifact Explorer MVP tab for Windows triage (resolver-based, not deep-parsed) with profile-aware path resolution, existence/status checks, cancellation support, and jump-to-filesystem/extract/copy-path actions.
- File browser upgrades: extension + logical path + allocated visibility, allocated/extension/path/status filters, and row-level context menu actions (extract/copy path/copy inode-jump parent/export metadata/open related artifact context).
- JSON/CSV metadata catalog export with generic timestamps and optional NTFS SI/FN timestamp preservation.

## Declared support scope (current milestone)
- **Primary image format targets:** RAW/DD and E01/EWF.
- **Primary filesystem targets:** NTFS, FAT32, exFAT, EXT3, EXT4.
- **Not currently claimed as supported targets:** ReFS, XFS.
- Generic TSK traversal may still enumerate other filesystems in some cases, but those paths are treated as unconfirmed and are surfaced with caution in the UI.

## E01 + TSK interoperability note
- `TskImageHandleAdapter` now attempts a reader-backed TSK image open first through `TskReaderBridge`.
- Reader-backed operation is the default production path for both RAW/DD and E01/EWF readers.
- Path-based TSK open is an explicit compatibility mode (`allowPathFallback=true`) and is not enabled by default.
- When compatibility mode is enabled and path fallback is used, the bridge failure is preserved as a warning (not a hard error).
- If both reader-backed and path-based open fail, the user receives a combined hard error message with both failure reasons.

## Metadata fidelity
Catalog records include:
- source image path
- partition identifier
- logical path
- file name
- size
- inode/file identifier
- deleted and allocated flags
- generic filesystem timestamps
- NTFS SI/FN timestamps when available
- ADS detection names when available on NTFS
- destination path
- SHA-256
- status
- error
- bytes written
- host timestamp apply status and error details

## Extraction edge-case handling
- ADS names are normalized (sorted + deduplicated) before catalog serialization for deterministic reporting.
- Deleted-entry extraction is explicitly marked with `source_entry_deleted` warning context.
- Short reads retain deterministic `short_read` outcome and include `bytes_written`, `expected`, and `possible_sparse_or_unreadable` context.
- Timestamp application failures are preserved as warnings and emitted into `host_timestamp_error` fields in JSON/CSV.
- Zero-byte files preserve size/hash/status fields without special-case omission.


## CLI mode (`fie_cli`)
The repository now includes a minimal production-usable headless executable that reuses the same engine (`fie_core`) used by the GUI.

### Commands
- `inspect`: open image + enumerate partitions
- `list`: open image + filesystem + list directory entries
- `extract`: extract a file/directory to destination root
- `catalog`: run extraction and emit metadata catalog (JSON/CSV)

### Exit codes
- `0`: success, no warnings
- `2`: success with warnings
- `1`: hard failure
- `64`: argument/usage error

### Examples
```bash
# Inspect partitions
./build/fie_cli inspect --image /evidence/case001.E01

# List root directory in partition p1
./build/fie_cli list --image /evidence/case001.E01 --partition p1 --path /

# Extract a directory recursively (reader-backed path is default)
./build/fie_cli extract --image /evidence/case001.E01 --partition p1 --source /Users --dest /exports/case001 --overwrite versioned

# Extract and emit JSON catalog
./build/fie_cli catalog --image /evidence/case001.E01 --partition p1 --source /Users --dest /exports/case001 --catalog-out /exports/case001/catalog.json --catalog-format json
```

`stderr` is reserved for deterministic `warning=` and `error=` lines; `stdout` emits machine-readable JSON payloads for successful command results.


## New GUI analysis workflows
- **Artifacts tab**: scan known Windows artifact paths for the selected partition, review status/size/timestamp context, extract selected artifact files, copy logical paths, and jump directly into the file browser context. Non-Windows suppression uses a lightweight heuristic (filesystem type + `/Windows` probe) to avoid noisy scans.
- **Enhanced file triage**: tuned for faster analyst scanning with compact triage filters, lightweight column profiles (triage/NTFS detail/extraction-status), denser sectioned metadata, bounded read-only hexdump preview with signature/truncation context, restrained row-state cues (deleted/unallocated/ADS/status), richer artifact↔file correlation cues, and right-click actions for extract/path+inode copy/parent navigation/metadata export/artifact cross-navigation.
- Scope remains read-only; this is a resolver-based Artifact Explorer MVP and deep parser views for SQLite/registry artifacts are intentionally deferred to future passes.

## Build requirements
- C++17
- CMake 3.21+
- Qt6 Core (required)
- Qt6 Widgets (required only when `FIE_ENABLE_GUI=ON`)
- The Sleuth Kit (TSK)
- libewf (optional but required for E01 read support)

## Build
```powershell
cmake -S . -B build -DFIE_ENABLE_TESTS=ON -DFIE_ENABLE_GUI=ON -DFIE_ENABLE_CLI=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```


## Developer notes
- See `ARCHITECTURE.md` for layer boundaries, runtime forensic flow, and warning/error semantics.
- See `DEVELOPER_NOTES.md` for stabilization decisions and rationale used in recent hardening passes.

## TSK/libewf discovery
CMake supports either system packages or direct cache variables:
- `TSK_INCLUDE_DIR`, `TSK_LIBRARY`
- `LIBEWF_INCLUDE_DIR`, `LIBEWF_LIBRARY`

- TSK open warnings are emitted separately from hard errors in worker/UI flow.
- Reader-backed bridge operation requires a build with TSK external-image callback support enabled (`FIE_HAS_TSK`).
- If TSK support is unavailable at build time, image open through TSK fails (reader-backed and path-based modes are both unavailable).

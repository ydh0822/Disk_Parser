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
- `artifacts scan`: resolver-driven artifact listing (optional parser-backed `--details` summary for supported artifact files)
- `artifacts timeline`: normalized artifact-event timeline/triage output (JSON by default, optional CSV)

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

# Artifact scan with conservative parser-backed details
./build/fie_cli artifacts scan --image /evidence/case001.E01 --partition p1 --details

# Build normalized artifact timeline in CSV
./build/fie_cli artifacts timeline --image /evidence/case001.E01 --partition p1 --output-format csv
```

`stderr` is reserved for deterministic `warning=` and `error=` lines; `stdout` emits machine-readable JSON payloads for successful command results.


## New GUI analysis workflows
- **Artifacts tab**: scan remains resolver-first and fast; parser-backed detail summaries for supported artifact files (`$Recycle.Bin/$I*`, `.lnk`, `.pf`, `.automaticdestinations-ms`, `SRUDB.dat`) load lazily when an artifact row is selected (with in-session caching and stale-result suppression). Extract/copy/jump actions are unchanged. Non-Windows suppression uses a lightweight heuristic (filesystem type + `/Windows` probe) to avoid noisy scans.
- **Browser SQLite coverage**: when built with optional SQLite support, Chrome/Edge `History` artifacts are parsed conservatively for visits/downloads and included in details + timeline events (`browser_visit`, `browser_download` / `browser_download_observed`).
- **Registry recent activity v1**: focused read-only REGF hive parsing for `NTUSER.DAT` resolver artifacts with conservative detail extraction for `RunMRU`, `TypedPaths`, `RecentDocs`, and `UserAssist` (this is intentionally not a generic registry explorer/editor).
- **System execution coverage v1**: focused read-only hive parsing for machine-level execution artifacts from `Amcache.hve` and `SYSTEM` BAM/DAM keys, surfaced through the same details + timeline pipeline.
- **Services v1**: focused read-only service configuration parsing from `SYSTEM\\<ActiveControlSet>\\Services\\<ServiceName>` for conservative fields (display/image/object/start/type/dependencies and optional `Parameters\\ServiceDll`), without execution inference.
- **Scheduled Tasks v1**: focused read-only XML task-definition parsing for files under `/Windows/System32/Tasks/**` with conservative triage fields (URI, principal/settings, Exec action fields, trigger/repetition summaries, optional registration date) and explicit nulls for absent fields.
- **WER v1**: focused read-only key/value parsing for `Report.wer` / `*.wer` files under `/ProgramData/Microsoft/Windows/WER/**` with conservative fields (event/app/module/exception/bucket/report metadata, optional problem-signature summaries, optional explicit report timestamp).
- **USB registry v1**: focused read-only parsing for `SYSTEM\\<ActiveControlSet>\\Enum\\USBSTOR\\...` via the existing USB registry resolver, with conservative device identity/configuration fields and optional key last-write timestamp.
- **EVTX v1 (focused)**: conservative **container-aware** `.evtx` parsing (file header + chunk + record traversal) with narrow EVTX/BinXML-aware raw field extraction (record/container validation plus conservative BinXML string-node interpretation) for files under `/Windows/System32/winevt/Logs/**` (first-class focus: `Security.evtx`, `System.evtx`, `Application.evtx`) and raw event-system fields only (no rendered message reconstruction).
- **SRUM metadata probe (narrow pass)**: focused read-only parsing of `/Windows/System32/sru/SRUDB.dat` as an ESE container with structure-backed page/tag parsing for supported SRUM table-identifier discovery. This pass does **not** include broad SRUM row decoding yet.
- **EVTX v2 Sysmon-first expansion**: `Microsoft-Windows-Sysmon/Operational.evtx` is now treated as first-class with conservative raw EventData-driven normalization for Event IDs `1,3,4,7,8,10,11,12-14,16,17-18,19-21,22,25` into dedicated timeline families (`sysmon_*`) while keeping generic `evtx_event` stable.
- **Sysmon channel correctness (v2.1 hardening)**: only the real Sysmon Operational channel (`Microsoft-Windows-Sysmon/Operational.evtx`) with Sysmon provider identity is mapped to `sysmon_*`; other `*/Operational.evtx` channels remain generic EVTX events.
- **Sysmon realism/fidelity hardening (v2.2)**: EVTX parser now supports a narrow template-substitution pattern in addition to direct text tokens, improving conservative recovery of System/EventData raw fields from more realistic Sysmon-like BinXML payload layouts.
- **Stabilization note (current pass)**: artifact platform external behavior is intentionally stable (provider contracts/JSON schema/timeline families unchanged) while internal EVTX parsing logic is decomposed into a dedicated narrow parser unit for maintainability/hardening.
- **Pre-SRUM stabilization/readiness (historical baseline)**: whole-codebase consistency review was completed before SRUM implementation, including epoch FILETIME correctness hardening and readiness validation.
- **Audit evidence (follow-up pass)**:
  - re-checked discovery/provider dispatch/CLI+GUI/timeline surfaces against current tests and contracts;
  - added regression for timeline failure visibility when provider names are unknown/unmapped (still emits `artifact_parse_status`);
  - explicitly documented duplicated FILETIME helper logic as a non-blocking maintainability hotspot kept unchanged for pre-SRUM stability.
- **EVTX fidelity hardening note (current pass)**: EVTX validation tightened (fragment/version/token/depth/name-reference integrity checks) with deterministic malformed-payload rejection and salvage-preserving container behavior; no scope widening into rendered-message/provider-DLL/publisher-metadata semantics.
- **AppCompatCache v1 (ShimCache)**: focused read-only parsing from `SYSTEM\\<ActiveControlSet>\\Control\\Session Manager\\AppCompatCache\\AppCompatCache` with conservative UTF-16 path extraction only (`utf16_path_scan_v1`). This pass intentionally treats execution/timestamp inference as trust-limited and emits those fields as `null`.
- **Jump List v1 (AutomaticDestinations)**: focused read-only DestList parsing for `.automaticdestinations-ms` files with explicit layout confidence gates and conservative entry linkage/target enrichment. Linked LNK streams are parsed using the existing Shell Link summary logic only as secondary enrichment (not as a generic compound-file browser). Unsupported or untrusted fields remain explicit `null`. `.customdestinations-ms` remains explicitly unsupported/deferred in this pass.
- **Artifacts tab** now includes an explicit **Analyze Artifacts** action for full-partition enrichment (user-triggered, background, cancellable) that populates the session cache and enables complete timeline/triage output without manually opening each row.
- **Timeline tab**: lightweight triage timeline view that derives normalized forensic events from available artifact details, with deterministic timestamp ordering and explicit untimed rows, plus export actions (JSON/CSV) and compact analysis summary counts.
- **Enhanced file triage**: tuned for faster analyst scanning with compact triage filters, lightweight column profiles (triage/NTFS detail/extraction-status), denser sectioned metadata, bounded read-only hexdump preview with signature/truncation context, restrained row-state cues (deleted/unallocated/ADS/status), richer artifact↔file correlation cues (explicit exact/parent/child reason labels), deterministic best-match artifact selection, clearer artifact-jump status messaging when filters hide a target row, and right-click actions for extract/path+inode copy/parent navigation/metadata export/artifact cross-navigation.
- Scope remains read-only; parser-backed summaries/events are intentionally conservative and deterministic. Unsupported types and parser failures do not abort scans. Artifact detail panel state is explicit (`loading`, `unsupported`, `parsed`, `partial`, `failed`). In CLI `--details` and timeline JSON, absent optional fields are emitted as explicit `null` values.
- Jump List trust model is explicit: for recognized trusted DestList layouts, `last_access_timestamp`, `access_count`, and `pinned` are emitted when conservative parsing succeeds; for trust-limited layouts they intentionally remain `null`.
- Timeline normalization now also includes registry event families: `registry_run_mru`, `registry_typed_path`, `registry_recent_doc`, and `userassist_execution` (untimed rows are preserved when no trusted timestamp exists).
- Timeline normalization also includes machine-level execution event families: `amcache_entry`, `bam_execution`, and `dam_execution`.
- Timeline normalization also includes AppCompatCache event families: `appcompatcache_entry_observed` (default untimed) and `appcompatcache_entry` (only when a trusted timestamp is explicitly present in parsed data).
- Timeline normalization also includes Services event families: `service_config_observed` (untimed default) and `service_config_modified` (only when a trustworthy service-key last-write timestamp exists).
- Timeline normalization also includes Scheduled Task event families: `scheduled_task_observed` (untimed default) and `scheduled_task_registered` (only when a trustworthy registration timestamp is explicitly present in task XML).
- Timeline normalization also includes WER event families: `wer_report_observed` (untimed default) and `wer_report_created` (only when a trustworthy explicit timestamp is present in parsed WER payload data).
- Timeline normalization also includes USB registry event families: `usb_device_observed` (untimed default) and `usb_device_registry_modified` (only when a trustworthy key timestamp is present on parsed USB instance keys).
- Timeline normalization also includes EVTX event family: `evtx_event` (timestamped when present; untimed rows preserved when trustworthy event timestamp is unavailable).
- Timeline normalization also includes SRUM probe event family: `srum_metadata_table_observed` (untimed table-presence context only from parsed page/tag payload discovery).
- Deferred in this pass: WER dump/CAB extraction, non-text WER payload families, deeper EVTX/SRUM expansion, and cross-artifact incident correlation.
- Deferred in this pass: broad USB session/timeline correlation (e.g., MountedDevices/user-hive shell artifacts), and any inference that registry presence alone proves interactive usage.
- Deferred in this pass: EVTX rendered-message reconstruction, provider DLL loading, publisher metadata resolution, higher-level semantic event-family interpretation, and cross-artifact incident correlation.
- Deferred to later major feature passes: deeper SRUM table/row coverage and broader cross-artifact semantic correlation.
- Timeline normalization includes Jump List event families: `jump_list_access` (timed) and `jump_list_entry_observed` (untimed when no trusted timestamp is available).
- TypedPaths is intentionally emitted via the `windows.registry_recent_docs` provider (single NTUSER.DAT recent-activity provider path) to avoid split-provider ambiguity.
- BAM/DAM parsing resolves active control set via `SYSTEM\\Select\\Current` when available and falls back conservatively to `ControlSet001` with a warning if resolution is unavailable/invalid.
- Amcache coverage is intentionally narrow to `Root\\InventoryApplication`-style entries and is not a generic Amcache explorer/parser.
- Workflow separation is explicit: resolver scan (fast), lazy row detail load (on-demand), and full analysis pass (explicit user action).
- SQLite-backed parsing uses read-only temporary materialization for path-based analyzers; evidence image content is never modified.

## Build requirements
- C++17
- CMake 3.21+
- Qt6 Core (required)
- Qt6 Widgets (required only when `FIE_ENABLE_GUI=ON`)
- The Sleuth Kit (TSK)
- libewf (optional but required for E01 read support)
- SQLite3 (optional; enables Chromium History detail/timeline coverage)

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

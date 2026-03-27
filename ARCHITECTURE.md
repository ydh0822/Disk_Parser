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
- `forensics::ArtifactDetailService` provides parser-backed detail enrichment for supported artifact files via pluggable providers (`IArtifactDetailProvider`), currently:
  - Recycle Bin `$I` summaries (original path, deletion timestamp, original size)
  - Shell Link (`.lnk`) conservative summaries (target/relative/workdir/args and basic timestamps when present)
  - Prefetch (`.pf`) conservative summaries (signature/version, executable name, run count, available last-run timestamps)
  - Chromium-family `History` (Chrome/Edge) conservative SQLite-backed visits/downloads when SQLite support is available
  - Focused read-only registry hive (`REGF`) traversal for `NTUSER.DAT` resolver artifacts:
    - `RunMRU`
    - `TypedPaths` (emitted under the same `windows.registry_recent_docs` provider path)
    - `RecentDocs`
    - `UserAssist`
  - Focused read-only system-hive execution coverage:
    - `Amcache.hve` (`Root\\InventoryApplication` only; narrow coverage)
    - `SYSTEM` BAM/DAM (`<ActiveControlSet>\\Services\\{bam|dam}\\State\\UserSettings`, where active set is resolved from `Select\\Current` with conservative fallback)
    - `SYSTEM` AppCompatCache v1 (`<ActiveControlSet>\\Control\\Session Manager\\AppCompatCache\\AppCompatCache`) with conservative `utf16_path_scan_v1` path extraction only
  - Services v1 coverage:
    - `SYSTEM\\<ActiveControlSet>\\Services\\<ServiceName>` focused configuration extraction only (display/image/start/type/object/description/dependencies/load-order/delayed-auto/optional `Parameters\\ServiceDll`)
  - Scheduled Tasks v1 coverage:
    - XML-backed task definitions under `/Windows/System32/Tasks/**` with focused extraction (URI/author/description, Exec action fields, principal/settings, trigger/repetition summaries, optional registration date)
  - WER v1 coverage:
    - text key/value `Report.wer` / `*.wer` payloads under `/ProgramData/Microsoft/Windows/WER/**` with conservative report/app/module/exception/bucket/report metadata and optional explicit report timestamp
  - USB registry v1 coverage:
    - `SYSTEM\\<ActiveControlSet>\\Enum\\USBSTOR\\...` focused traversal for conservative USB device identity/configuration fields and optional key last-write timestamp
  - EVTX v1 (focused) coverage:
    - `.evtx` files under `/Windows/System32/winevt/Logs/**` with conservative container-aware parsing (file/chunk/record traversal) and narrow EVTX/BinXML-aware raw system-field extraction (no rendered message reconstruction)
  - SRUM metadata probe coverage (narrow pass, not full SRUM v1 semantics):
    - `/Windows/System32/sru/SRUDB.dat` focused ESE-container metadata validation
    - structure-backed page/tag parsing is used to discover supported SRUM table identifiers from parsed tag payloads
    - row-level decoding is intentionally deferred
  - Jump List v1 coverage:
    - `.automaticdestinations-ms` via focused CFBF/DestList parsing with explicit layout-recognition gates
    - linked LNK stream enrichment reuses the existing Shell Link summary parser and is applied conservatively (secondary to trusted DestList path fields)
    - `.customdestinations-ms` is explicitly unsupported/deferred in this pass
- Registry parsing scope is intentionally narrow and production-minded: only key/value traversal required for these artifacts is implemented; this milestone is not a generic registry explorer/browser.
- Detail parsing is explicitly read-only and deterministic; each artifact detail result is `Parsed`, `Partial`, or `Failed`. Unsupported types remain unmodified and are not treated as errors.
- Jump List v1 trust semantics are explicit: layout-dependent trust-limited fields (`last_access_timestamp`, `access_count`, `pinned`) are emitted only when a recognized trusted DestList entry layout is matched; otherwise they remain null by design.
- AppCompatCache v1 trust semantics are explicit: this pass treats cache path presence as triage context only and does not claim execution certainty; execution/timestamp fields remain null unless a future trusted format parser supports them.
- Services v1 trust semantics are explicit: service registration/configuration is treated as configuration evidence only and must not be interpreted as confirmed execution.
- Scheduled Tasks v1 trust semantics are explicit: task-definition presence/configuration is treated as configuration evidence only and must not be interpreted as confirmed execution.
- WER v1 trust semantics are explicit: report presence is treated as report-generation context only; execution/crash timing is not inferred unless an explicit trustworthy timestamp is present in the report payload.
- USB registry v1 trust semantics are explicit: registry device presence/configuration is treated as device-registration context only and must not be interpreted as confirmed interactive user activity.
- EVTX v1 trust semantics are explicit: only conservatively extracted raw fields are emitted (`record_id`, provider/system fields, trusted timestamp when available, and event_data key/value only when confidently parsed); missing/untrusted fields remain null and no higher-level semantics are inferred.
- Stabilization/decomposition pass (current): external artifact-platform behavior is intentionally kept stable while EVTX BinXML parsing is isolated into a dedicated internal parser unit to reduce coupling and improve maintainability.
- EVTX validation/fidelity hardening pass (current): parser now applies stricter fragment/token/name-reference/depth integrity checks with deterministic malformed-payload rejection while preserving container-level salvage semantics.
- EVTX v2 Sysmon-first channel support: `Microsoft-Windows-Sysmon/Operational.evtx` is treated as first-class for conservative EventData-based normalization (`sysmon_process_create`, `sysmon_network_connect`, `sysmon_image_load`, `sysmon_remote_thread`, `sysmon_process_access`, `sysmon_file_create`, `sysmon_registry_event`, `sysmon_named_pipe`, `sysmon_wmi_event`, `sysmon_dns_query`, `sysmon_process_tampering`, `sysmon_service_state_change`, `sysmon_config_change`) while generic `evtx_event` remains unchanged.
- EVTX v2.1 channel-identity hardening: Sysmon normalization requires real Sysmon channel/provider identity; non-Sysmon `Operational.evtx` channels are intentionally kept on generic `evtx_event` only.
- EVTX v2.2 realism hardening: narrow template-substitution token handling is supported in EVTX BinXML parsing to better recover conservative raw Sysmon fields from realistic payload variants while preserving strict bounds/validation behavior.
- Pre-SRUM whole-codebase stabilization/review (historical baseline): discovery/detail providers, CLI/GUI serialization surfaces, and timeline normalization were reviewed end-to-end for consistency; external artifact-platform behavior stayed intentionally stable (provider names, JSON schema shape, timeline family names, and explicit null semantics).
- Pre-SRUM correctness hardening (historical baseline): FILETIME-to-UTC conversion preserves exactly-epoch (`1970-01-01T00:00:00Z`) values instead of collapsing them to null.
- Pre-SRUM readiness audit follow-up (historical baseline): no architecture-level blockers were identified for SRUM integration; provider/timeline growth pressure was documented as a maintainability hotspot with adequate regression guardrails.
- Audit evidence (follow-up):
  - Discovery/detail/timeline coverage parity for current families re-checked against existing service/tests; no contract changes required.
  - CLI details/timeline JSON explicit-null behavior re-checked; no schema changes made in this pass to preserve consumer stability.
  - GUI detail/caching/stale-result handling reviewed against session/cache tests; no grounded behavior bug found in current flow.
  - Added regression that unknown provider parse failures still emit `artifact_parse_status`, protecting timeline failure visibility during future provider expansion.
  - Duplicate FILETIME conversion helpers remain intentionally duplicated across detail-provider and registry-hive modules as a documented non-blocking maintainability hotspot (deferred consolidation to avoid pre-SRUM refactor risk).
- CLI `fie_cli artifacts scan --details` remains explicit opt-in eager enrichment; absent optional parsed fields serialize as `null` in JSON detail payloads for deterministic machine interpretation.
- Path-based artifact parsers (e.g., SQLite-backed browser History) use read-only temporary artifact materialization via `ArtifactMaterializationService` and never modify evidence content.
- `forensics::ArtifactTimelineService` normalizes parser-backed details into compact `domain::ArtifactEventRecord` rows for triage/timeline workflows; events preserve source artifact context and do not fabricate timestamps.
- Supported normalization sources:
  - Recycle Bin `$I`: deletion event + original path/size context
  - `.lnk`: created/modified/accessed events when timestamps exist
  - `.pf`: last-run events (or untimed observed execution context when only non-time fields are available)
  - Chromium History: `browser_visit`, `browser_download`, `browser_download_observed`
  - Registry recent activity: `registry_run_mru`, `registry_typed_path`, `registry_recent_doc`, `userassist_execution`
  - System-level execution: `amcache_entry`, `bam_execution`, `dam_execution`
  - AppCompatCache v1: `appcompatcache_entry_observed` (untimed by default), `appcompatcache_entry` (only when trusted timestamp exists)
  - Services v1: `service_config_observed`, `service_config_modified` (only when service-key last-write timestamp is available)
  - Scheduled Tasks v1: `scheduled_task_observed`, `scheduled_task_registered` (only when task XML contains a trusted registration timestamp)
  - WER v1: `wer_report_observed`, `wer_report_created` (only when explicit trusted report timestamp exists)
  - USB registry v1: `usb_device_observed`, `usb_device_registry_modified` (only when USB instance key last-write timestamp is available)
  - EVTX v1 (focused): `evtx_event` (timed when event `SystemTime` is present; untimed otherwise)
  - SRUM metadata probe: `srum_metadata_table_observed` (untimed, emitted only for recognized supported table identifiers discovered from parsed page/tag payloads)
  - Jump Lists: `jump_list_access`, `jump_list_entry_observed`
- `workers::ArtifactScanWorker` wires GUI async execution to resolver-only discovery and returns artifact rows plus a single structured operation result; scan warnings are carried in `ForensicOperationResult.diagnostic.detail` when `state=SuccessWithWarning`.
- GUI parser-backed details are loaded via a dedicated on-demand worker (`workers::ArtifactDetailWorker`) per selected artifact row, not during scan.
- GUI full-partition enrichment is handled by a dedicated explicit worker (`workers::ArtifactAnalysisWorker`) that processes supported present artifact files, populates the same session cache used by lazy loading, reports progress, and remains cancel-safe.
- Stale-result suppression is explicit (selection/request-key matching) and in-flight detail work is cancel-safe across selection changes, rescans, and context switches.
- GUI keeps a session-local in-memory artifact-detail cache keyed by `partitionIdentifier + logicalPath`; cache is invalidated on image/partition context changes and is never persisted.
- GUI timeline view is a lightweight table derived from current artifact rows + loaded/cached details using `ArtifactTimelineService`; ordering is deterministic by timestamp with explicit untimed rows.
- GUI exposes explicit triage export from the timeline view (JSON/CSV), aligned to the CLI timeline schema (`ArtifactTimelineJson`).
- Missing resolver targets are represented as `ArtifactRecord.status="Missing"` (not warnings); warnings are reserved for traversal/listing failures and cancellation/error conditions.
- `gui::ArtifactTableModel` and the MainWindow `Artifacts` tab provide scan/extract/copy/jump actions while reusing existing extraction/catalog plumbing.
- Artifact scan entry is softly gated by a lightweight heuristic (partition FS type + `/Windows` root presence probe) to avoid noisy scans on clearly non-Windows targets; this is intentionally best-effort, not authoritative OS detection.

## File browser upgrade (Phase 2 incremental)
- `FileEntryTableModel` exposes additional forensic triage columns (logical path + allocated state) while preserving existing timestamp/ADS metadata surfaces.
- `FileEntryFilterProxyModel` now supports allocated-only, extension, path-content, and row-status filters in addition to existing deleted/type/ADS/name filters.
- File table context menu adds examiner-centric actions: extract, copy logical path, jump parent, export row metadata, and open related artifact context; correlation is intentionally path-only (exact/ancestor/descendant), exposes reason labels in UI metadata/status, and keeps deterministic ranking (exact > ancestor > descendant) for analyst auditability.
- Metadata shown in the browser remains sourced from existing `forensics::FileSystemBrowser` (TSK directory/meta fields + NTFS-specific enrichment where available).
- Artifact selection metadata includes parser-backed details for supported artifact types via lazy loading, while unsupported artifacts cleanly fall back to resolver metadata + correlation context.

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

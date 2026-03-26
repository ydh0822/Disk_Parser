# Developer Notes

## Stabilization decisions (final cleanup pass)

1. **Deleted entry classification**
   - Allocation/deleted state now uses both TSK name and metadata unallocated flags where available to avoid contradictory reporting.

2. **ADS determinism**
   - NTFS ADS names are normalized (sorted + deduplicated) before catalog serialization for reproducible CSV/JSON output.

3. **Short-read forensic context**
   - Short reads preserve deterministic `short_read` outcome and carry explicit warning context including `bytes_written`, `expected`, and `possible_sparse_or_unreadable`.

4. **Deleted-source traceability**
   - Extraction of deleted entries appends `source_entry_deleted` warning context to improve analyst visibility without converting warnings into hard errors.

5. **Path-fallback compatibility policy**
   - Reader-backed TSK open remains default; path-based open is compatibility mode and must be explicitly enabled with `allowPathFallback=true`.

## 2026-03 Artifact Explorer + Browser Triage Increment
- Added a profile-aware artifact discovery service (`ArtifactDiscoveryService`) that performs resolver-first Windows artifact triage for the selected partition.
- Added GUI `Artifacts` tab with scan/extract/jump/copy actions and warning surfacing for partial resolver failures.
- Added parser-backed artifact detail enrichment (`ArtifactDetailService` + provider abstraction) for `$Recycle.Bin/$I*`, `.lnk`, and `.pf` with explicit `Parsed`/`Partial`/`Failed` semantics and warning propagation.
- Added optional CLI detail emission (`fie_cli artifacts scan --details`) with stable nested `details` JSON payloads for supported artifacts; unsupported artifacts serialize with `details: null`.
- Refined GUI orchestration to keep artifact scan resolver-first: parser-backed details now load lazily on artifact-row selection via a dedicated worker, with stale-result suppression + cancellation-safe handling.
- Added session-local artifact-detail caching keyed by partition+logical-path, invalidated on context changes (image/partition/rescan) to avoid repeated parsing in one session.
- Hardened CLI `--details` JSON semantics so absent optional parsed fields serialize as explicit `null` (avoiding ambiguous sentinel `0`/empty-string values).
- Added normalized artifact-event model (`ArtifactEventRecord`) and timeline normalization service (`ArtifactTimelineService`) to derive compact triage events from supported parser-backed details.
- Added CLI `artifacts timeline` output (JSON default, optional CSV) and lightweight GUI Timeline tab derived from currently available loaded/cached details.
- Clarified detail-panel UX states to explicitly distinguish loading vs unsupported vs parsed/partial/failed.
- Added explicit GUI full-partition analysis workflow (`Analyze Artifacts`) powered by `ArtifactAnalysisWorker` to enrich all supported present artifact files for the selected partition in the background.
- Full analysis pass populates the same session-local cache used by lazy row selection, reports progress, and supports deterministic cancellation/stale-result suppression.
- Timeline view now includes compact triage summary counts and export actions (JSON/CSV) using the same normalized event schema as CLI timeline output.
- Fixed analysis stale-result context-key mismatch between GUI and worker so completed analysis results are now applied deterministically.
- Added optional SQLite-backed Chromium History parsing (Chrome/Edge) with conservative visit/download extraction and timeline normalization (`browser_visit`, `browser_download`, `browser_download_observed`).
- Added read-only temporary artifact materialization helper for path-based parsers (`ArtifactMaterializationService`) to support SQLite workflows without mutating evidence.
- Added Registry-backed Recent Activity v1 using a focused read-only hive parser (`RegistryHive`) for narrow key/value traversal only (not a generic registry browser).
- Added parser-backed registry detail providers for `RunMRU`, `TypedPaths`, `RecentDocs`, and `UserAssist` keyed from resolver outputs against `NTUSER.DAT`.
- Extended timeline normalization with registry event families: `registry_run_mru`, `registry_typed_path`, `registry_recent_doc`, `userassist_execution`.
- Added focused synthetic-hive tests for registry parser helpers, provider extraction semantics, timeline normalization, and JSON null behavior.
- Added system execution coverage v1 with focused providers for `Amcache.hve` and SYSTEM BAM/DAM user-settings keys.
- Added normalized timeline event coverage for `amcache_entry`, `bam_execution`, and `dam_execution`.
- Hardened BAM/DAM control set handling: active control set now resolves from `SYSTEM\\Select\\Current` when available, with deterministic warning-backed fallback to `ControlSet001`.
- Added Jump List v1 provider (`windows.jump_list_v1`) with read-only AutomaticDestinations DestList parsing and explicit null/partial semantics for unavailable fields.
- Extended timeline normalization with Jump List event families: `jump_list_access` and `jump_list_entry_observed`.
- Clarified Jump List scope boundary: `.customdestinations-ms` remains intentionally unsupported/deferred for now.
- Hardened Jump List v1 parser confidence rules: trusted DestList metrics are now layout-gated, with trust-limited layouts explicitly emitting null for timestamp/pin/access_count instead of guessed values.
- Added conservative linked-stream enrichment by reusing existing LNK summary parsing for streamNumber-resolved Jump List streams; DestList target path retains precedence.
- Added AppCompatCache (ShimCache) v1 provider (`windows.appcompatcache_v1`) from SYSTEM hive resolver artifacts using active-control-set resolution and focused read-only key/value parsing.
- AppCompatCache v1 currently supports conservative `utf16_path_scan_v1` extraction (path + index + source path) with deterministic nulls for trust-limited execution/timestamp semantics.
- Extended timeline normalization for AppCompatCache with `appcompatcache_entry_observed` (default untimed) and `appcompatcache_entry` (only when trusted timestamps are present in parsed data).
- Added Services v1 provider (`windows.services_v1`) for `Services hive resolver` artifacts with focused active-control-set parsing of `SYSTEM\\...\\Services\\<ServiceName>` keys and conservative configuration field extraction.
- Added Services timeline normalization (`service_config_observed` / `service_config_modified`) with explicit caveat that service configuration does not imply confirmed execution.
- Added Scheduled Tasks v1 provider (`windows.scheduled_task_v1`) for XML-backed definitions under `/Windows/System32/Tasks/**` with conservative triage extraction only.
- Added Scheduled Tasks timeline normalization (`scheduled_task_observed` / `scheduled_task_registered`) with explicit caveat that task definition presence does not imply confirmed execution.
- Hardened Scheduled Tasks XML decoding to respect BOM/encoding more conservatively (no UTF-8-only assumption) with regression coverage for UTF-16 BOM input.
- Added WER v1 provider (`windows.wer_v1`) for text-based `Report.wer` / `*.wer` payloads under `/ProgramData/Microsoft/Windows/WER/**` with conservative key/value extraction and explicit null handling for absent/trust-limited fields.
- Added WER timeline normalization (`wer_report_observed` / `wer_report_created`) with strict timestamp trust semantics (only explicit trustworthy report timestamps are timed).
- Added USB registry v1 provider (`windows.usb_registry_v1`) for `USB registry resolver` SYSTEM artifacts with focused `Enum\\USBSTOR` extraction and conservative device identity/configuration fields.
- Added USB timeline normalization (`usb_device_observed` / `usb_device_registry_modified`) with explicit caveat that registry presence/configuration does not confirm interactive usage.
- Hardened focused EVTX v1 provider (`windows.evtx_v1`) to a narrow real EVTX/BinXML-aware extraction path: container validation (header/chunk/record), conservative BinXML string-node interpretation for trustworthy raw fields (`record_id`, provider/system fields, trusted timestamp, optional `event_data` key/value), and deterministic malformed-payload warnings/salvage behavior.
- Stabilization/decomposition follow-up: EVTX BinXML parsing is now isolated in a dedicated internal parser file (`src/forensics/detail_providers/EvtxBinXmlParser.cpp`) so provider orchestration remains stable while parser hardening can evolve with less coupling.
- EVTX validation/fidelity hardening follow-up: strict fragment/version/token/depth/name-reference checks were added to reduce silent acceptance of malformed synthetic payloads while preserving deterministic warning/salvage behavior at the container layer.
- EVTX v2 Sysmon-first expansion: Sysmon Operational channel is now first-class and emits conservative `sysmon_*` normalized events for IDs `1,3,4,7,8,10,11,12-14,16,17-18,19-21,22,25` using only raw System/EventData fields (no rendered-message/provider-DLL/publisher resolution).
- EVTX v2.1 correctness hardening: Sysmon normalization now requires both real Sysmon channel identity (`Microsoft-Windows-Sysmon/Operational.evtx`) and Sysmon provider identity; generic `Operational.evtx` channels are no longer implicitly treated as Sysmon.
- EVTX v2.2 realism/fidelity hardening: parser now supports a narrow inline template-substitution token pattern in addition to direct text tokens, improving conservative extraction from more realistic Sysmon-like BinXML payload variants.
- Added EVTX timeline normalization (`evtx_event`) with timestamp preservation only when trustworthy event `SystemTime` is explicitly present.
- Clarified provider boundary: TypedPaths remains intentionally integrated in the `windows.registry_recent_docs` flow (no standalone TypedPaths provider registration).
- Hardened GUI detail rendering with compact registry/system-execution entry counts and previews for analyst visibility.
- Enhanced file triage table/filtering and right-click context actions to support examiner workflows without changing read-only extraction semantics.
- Deferred: deeper registry ecosystems beyond recent-activity + system-execution v1 (broader AppCompatCache formats, richer Services SCM semantics, SAM/SECURITY deep parsing), advanced Task Scheduler correlation/legacy `.job` parsing, EVTX rendered-message reconstruction/provider DLL loading/publisher metadata resolution, Jump List CustomDestinations parsing, WER dump/CAB/non-text payload parsing, broad USB session/mounted-device/user-hive correlation, timeline correlation, and broader artifact parser coverage.
- Deferred next major feature pass: SRUM v1 coverage and broader multi-artifact semantic correlation.
- Validation note: directory-target artifacts (e.g., Prefetch/Downloads/Startup/Tasks/EVTX root) now flow through the same `startExtractionTask` path used by standard file extraction, so recursive directory extraction semantics and progress/catalog reporting are shared.

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
- Clarified provider boundary: TypedPaths remains intentionally integrated in the `windows.registry_recent_docs` flow (no standalone TypedPaths provider registration).
- Hardened GUI detail rendering with compact registry/system-execution entry counts and previews for analyst visibility.
- Enhanced file triage table/filtering and right-click context actions to support examiner workflows without changing read-only extraction semantics.
- Deferred: deeper registry ecosystems beyond recent-activity + system-execution v1 (full AppCompatCache, SAM/SECURITY deep parsing), EVTX/JumpList parsing, timeline correlation, and broader artifact parser coverage.
- Validation note: directory-target artifacts (e.g., Prefetch/Downloads/Startup/Tasks/EVTX root) now flow through the same `startExtractionTask` path used by standard file extraction, so recursive directory extraction semantics and progress/catalog reporting are shared.

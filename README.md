# Forensic Image Extractor

Forensic Image Extractor is a Qt 6 Widgets desktop application for read-only forensic image analysis and extraction.

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
- JSON/CSV metadata catalog export with generic timestamps and optional NTFS SI/FN timestamp preservation.

## E01 + TSK interoperability note
- `TskImageHandleAdapter` now attempts a reader-backed TSK image open first through `TskReaderBridge`.
- For libewf-backed E01/EWF images, TSK is now fed through the `IImageReader` callback bridge as the primary operational path.
- Path-based TSK open remains available only as a fallback path and is surfaced as a warning (not a hard error) when used.
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

## Build requirements
- C++17
- CMake 3.21+
- Qt6 Widgets
- The Sleuth Kit (TSK)
- libewf (optional but required for E01 read support)

## Build
```powershell
cmake -S . -B build -DFIE_ENABLE_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

## TSK/libewf discovery
CMake supports either system packages or direct cache variables:
- `TSK_INCLUDE_DIR`, `TSK_LIBRARY`
- `LIBEWF_INCLUDE_DIR`, `LIBEWF_LIBRARY`

- TSK open warnings are emitted separately from hard errors in worker/UI flow.
- Reader-backed bridge operation requires a build with TSK external-image callback support enabled (`FIE_HAS_TSK`).
- If TSK support is unavailable at build time, reader-backed open is skipped and path-based open remains the only available mode.

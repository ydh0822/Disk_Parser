# Architecture

## Layers
- `core`: image readers and TSK image adapter.
- `domain`: forensic entities and extraction/catalog records.
- `forensics`: partition enumeration, filesystem access, NTFS browsing, extraction.
- `workers`: threaded workers for open/scan/list/extract.
- `utils`: logging, hashing, serialization, path handling, timestamp policy.
- `gui`: Qt Widgets presentation and orchestration.

## Real forensic path (RAW/DD)
1. `RawImageReader` opens image read-only.
2. `TskImageHandleAdapter` opens a `TSK_IMG_INFO`.
3. `VolumeEnumerator` parses partition table via `tsk_vs_open`.
4. `FileSystemHandle` opens partition filesystem via `tsk_fs_open_img`.
5. `NtfsBrowser` lists directory entries from `tsk_fs_dir_open` + `tsk_fs_dir_get`.
6. `ExtractionService` recursively expands directories and streams file data in chunks via `tsk_fs_file_read`.

## E01 interoperability status
- `EwfImageReader` is real libewf-backed (`open/size/read`) including segmented-set discovery.
- `TskImageHandleAdapter` now explicitly separates two backends:
  - reader-bridge backend (planned callback-backed `IImageReader` integration)
  - path-based backend (current operational fallback)
- This makes the E01+TSK gap explicit without pretending full callback bridge completion yet.

## Timestamp handling
- SI timestamps come from `TSK_FS_META`.
- FN timestamps come from `TSK_FS_NAME`.
- SI/FN remain separate in model, UI, and exports.
- Host timestamp application is optional and recorded per extraction item.

## Warning/error separation
- TSK adapter fallback warnings are surfaced as warnings (not hard errors) through worker signals.

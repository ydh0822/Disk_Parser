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

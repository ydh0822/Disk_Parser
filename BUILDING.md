# Building Forensic Image Extractor

## Configure
`cmake -S . -B build -DFIE_ENABLE_TESTS=ON`

## Build
`cmake --build build --config Release`

## Run tests
`ctest --test-dir build --output-on-failure -C Release`

## Notes
- If TSK or libewf are not discovered, related functionality is compiled out.
- Install Qt 6 development packages before configure.
- Optionally provide `TSK_INCLUDE_DIR`/`TSK_LIBRARY` and `LIBEWF_INCLUDE_DIR`/`LIBEWF_LIBRARY`.

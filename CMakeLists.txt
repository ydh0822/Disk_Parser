cmake_minimum_required(VERSION 3.21)
project(ForensicImageExtractor VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

option(FIE_ENABLE_GUI "Build Qt Widgets GUI" ON)
option(FIE_ENABLE_CLI "Build headless CLI" ON)

option(FIE_ENABLE_TESTS "Build tests" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(Qt6 COMPONENTS Widgets)
find_package(TSK)
find_package(LIBEWF)

add_library(fie_core
  src/core/ImageReaderFactory.cpp
  src/core/EwfImageReader.cpp
  src/core/EwfSegmentResolver.cpp
  src/core/RawImageReader.cpp
  src/core/ReadCache.cpp
  src/core/TskImageHandleAdapter.cpp
  src/core/TskExternalImageApi.cpp
  src/core/TskReaderBridge.cpp
  src/domain/Models.cpp
  src/forensics/VolumeEnumerator.cpp
  src/forensics/FileSystemHandle.cpp
  src/forensics/FileSystemBrowser.cpp
  src/forensics/NtfsBrowser.cpp
  src/forensics/ExtractionService.cpp
  src/forensics/ArtifactDiscoveryService.cpp
  src/utils/Error.cpp
  src/utils/LogManager.cpp
  src/utils/PathUtils.cpp
  src/utils/MetadataFactory.cpp
  src/utils/TimestampSerializer.cpp
  src/utils/HashCalculator.cpp
  src/utils/MetadataSerializerCsv.cpp
  src/utils/MetadataSerializerJson.cpp
  src/utils/TimestampPolicy.cpp
  src/utils/ExtractionPlanner.cpp
  src/cli/CliOptions.cpp
)

target_include_directories(fie_core PUBLIC include)

target_link_libraries(fie_core PUBLIC Qt6::Core)

if(TSK_FOUND)
  target_compile_definitions(fie_core PUBLIC FIE_HAS_TSK=1)
  target_link_libraries(fie_core PUBLIC TSK::tsk)
endif()

if(LIBEWF_FOUND)
  target_compile_definitions(fie_core PUBLIC FIE_HAS_LIBEWF=1)
  target_link_libraries(fie_core PUBLIC LIBEWF::libewf)
endif()

if(MSVC)
  target_compile_options(fie_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(fie_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(FIE_ENABLE_GUI)
  if(NOT TARGET Qt6::Widgets)
    message(FATAL_ERROR "FIE_ENABLE_GUI=ON but Qt6::Widgets was not found")
  endif()

  add_library(fie_workers
    src/workers/TaskRunner.cpp
    src/workers/ExtractionWorker.cpp
    src/workers/ForensicsWorkers.cpp
    src/workers/WorkerOutcomePolicy.cpp
  )

  target_link_libraries(fie_workers PUBLIC fie_core Qt6::Core)

  add_executable(ForensicImageExtractor
    src/app/main.cpp
    src/gui/MainWindow.cpp
    src/gui/FileEntryTableModel.cpp
    src/gui/ArtifactTableModel.cpp
  )

  target_link_libraries(ForensicImageExtractor PRIVATE fie_workers Qt6::Widgets)
endif()

if(FIE_ENABLE_CLI)
  add_executable(fie_cli
    src/cli/main.cpp
  )
  target_link_libraries(fie_cli PRIVATE fie_core Qt6::Core)
endif()

if(FIE_ENABLE_TESTS)
  enable_testing()
  add_executable(fie_tests
    tests/test_main.cpp
    tests/test_PathUtils.cpp
    tests/test_MetadataRecord.cpp
    tests/test_TimestampSerialization.cpp
    tests/test_OverwritePolicy.cpp
    tests/test_HashCalculator.cpp
    tests/test_ChunkPlan.cpp
    tests/test_RecursivePathHandling.cpp
    tests/test_MetadataExportFields.cpp
    tests/test_RecursiveVisitedHandling.cpp
    tests/test_BackendWarningSemantics.cpp
    tests/test_ImageReaderFactoryRouting.cpp
    tests/test_EwfSegmentDiscovery.cpp
    tests/test_ExtractionStatusSemantics.cpp
    tests/test_FileSystemMetadataModel.cpp
    tests/test_ReadCache.cpp
    tests/test_ExtractionCancellationAndProgress.cpp
    tests/test_TskReaderBridge.cpp
    tests/test_EndToEndSemantics.cpp
    tests/test_CliOptions.cpp
    tests/test_ForensicEdgeCases.cpp
    tests/test_ArtifactDiscoveryService.cpp
    tests/test_ForensicOperationResult.cpp
    tests/test_WorkerResultSemantics.cpp
    tests/test_FileEntryFiltering.cpp
    tests/test_FileEntryTableVisualCues.cpp
    tests/test_CorrelationUtils.cpp
    tests/test_NavigationUtils.cpp
    tests/test_ArtifactCorrelationFlow.cpp
    tests/test_CliArtifactJson.cpp
    src/gui/FileEntryTableModel.cpp
    src/gui/ArtifactTableModel.cpp
  )
  target_include_directories(fie_tests PRIVATE src)
  if(TARGET fie_workers)
    target_link_libraries(fie_tests PRIVATE fie_workers Qt6::Core)
  else()
    add_library(fie_workers_for_tests
      src/workers/TaskRunner.cpp
      src/workers/ExtractionWorker.cpp
      src/workers/ForensicsWorkers.cpp
      src/workers/WorkerOutcomePolicy.cpp
    )
    target_link_libraries(fie_workers_for_tests PUBLIC fie_core Qt6::Core)
    target_link_libraries(fie_tests PRIVATE fie_workers_for_tests Qt6::Core)
  endif()
  add_test(NAME fie_tests COMMAND fie_tests)
endif()

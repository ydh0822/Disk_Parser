#include <iostream>

int runPathUtilsTests();
int runTimestampSerializationTests();
int runMetadataRecordTests();
int runOverwritePolicyTests();
int runHashCalculationTests();
int runMetadataExportFieldTests();
int runRecursivePathHandlingTests();
int runChunkPlanTests();
int runRecursiveVisitedHandlingTests();
int runBackendWarningSemanticsTests();
int runImageReaderFactoryRoutingTests();
int runEwfSegmentDiscoveryTests();
int runExtractionStatusSemanticsTests();
int runFileSystemMetadataModelTests();
int runReadCacheTests();
int runExtractionCancellationAndProgressTests();

int main() {
  const int rc = runPathUtilsTests() + runTimestampSerializationTests() + runMetadataRecordTests() +
                 runOverwritePolicyTests() + runHashCalculationTests() + runMetadataExportFieldTests() +
                 runRecursivePathHandlingTests() + runChunkPlanTests() + runEwfSegmentDiscoveryTests() +
                 runImageReaderFactoryRoutingTests() + runBackendWarningSemanticsTests() +
                 runRecursiveVisitedHandlingTests() + runExtractionStatusSemanticsTests() +
                 runFileSystemMetadataModelTests() + runReadCacheTests() +
                 runExtractionCancellationAndProgressTests();
  if (rc == 0) {
    std::cout << "All tests passed\n";
  }
  return rc;
}

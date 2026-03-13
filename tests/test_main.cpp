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
int runTskReaderBridgeTests();
int runEndToEndSemanticsTests();
int runCliOptionsTests();
int runForensicEdgeCaseTests();
int runArtifactDiscoveryServiceTests();
int runForensicOperationResultTests();
int runWorkerResultSemanticsTests();
int runFileEntryFilteringTests();
int runFileEntryTableVisualCueTests();
int runCorrelationUtilsTests();
int runNavigationUtilsTests();
int runArtifactCorrelationFlowTests();
int runCliArtifactJsonTests();

int main() {
  const int rc = runPathUtilsTests() + runTimestampSerializationTests() + runMetadataRecordTests() +
                 runOverwritePolicyTests() + runHashCalculationTests() + runMetadataExportFieldTests() +
                 runRecursivePathHandlingTests() + runChunkPlanTests() + runEwfSegmentDiscoveryTests() +
                 runImageReaderFactoryRoutingTests() + runBackendWarningSemanticsTests() +
                 runRecursiveVisitedHandlingTests() + runExtractionStatusSemanticsTests() +
                 runFileSystemMetadataModelTests() + runReadCacheTests() +
                 runExtractionCancellationAndProgressTests() + runTskReaderBridgeTests() +
                 runEndToEndSemanticsTests() + runCliOptionsTests() + runForensicEdgeCaseTests() +
                 runArtifactDiscoveryServiceTests() + runForensicOperationResultTests() + runWorkerResultSemanticsTests() +
                 runFileEntryFilteringTests() + runFileEntryTableVisualCueTests() + runCorrelationUtilsTests() +
                 runNavigationUtilsTests() + runArtifactCorrelationFlowTests() + runCliArtifactJsonTests();
  if (rc == 0) {
    std::cout << "All tests passed\n";
  }
  return rc;
}

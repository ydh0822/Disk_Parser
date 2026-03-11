#include "ForensicImageExtractor/utils/ExtractionPlanner.h"

int runRecursivePathHandlingTests() {
  const auto sanitized = fie::utils::sanitizeLogicalPath("/A<bad>/B:C/file.txt");
  if (sanitized != "A_bad_/B_C/file.txt") return 1;

  const auto composed = fie::utils::composeDestinationPath("C:/out", "/A/B");
  if (!composed.endsWith("A/B") && !composed.endsWith("A\\B")) return 1;

  return 0;
}

#include "ForensicImageExtractor/utils/ExtractionPlanner.h"

int runExtractionStatusSemanticsTests() {
  const auto base = fie::utils::successOutcomeFromDecision("overwrite");
  if (base != "success_overwrite") return 1;

  const auto withWarn = fie::utils::finalStatusFromOutcome("success_overwrite", true, false);
  if (withWarn != "success_with_warning") return 1;

  const auto shortRead = fie::utils::finalStatusFromOutcome("short_read", true, false);
  if (shortRead != "short_read") return 1;

  const auto zeroDefault = fie::utils::successOutcomeFromDecision("new");
  if (zeroDefault != "success") return 1;

  const auto zeroVersioned = fie::utils::successOutcomeFromDecision("versioned_copy");
  if (zeroVersioned != "success_versioned") return 1;

  return 0;
}

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"

int runBackendWarningSemanticsTests() {
  // True successful fallback semantics.
  const auto ok = fie::core::TskImageHandleAdapter::resolveOpenOutcomeForTesting(
      "Reader-backed TSK bridge unavailable", true, "");
  if (!ok.success) return 1;
  if (!ok.error.isEmpty()) return 1;
  if (ok.warning.isEmpty()) return 1;
  if (ok.backend != fie::core::TskOpenBackend::PathBased) return 1;

  // Failure semantics still return hard error.
  const auto fail = fie::core::TskImageHandleAdapter::resolveOpenOutcomeForTesting(
      "Reader-backed TSK bridge unavailable", false, "TSK path open failed");
  if (fail.success) return 1;
  if (fail.error.isEmpty()) return 1;
  return 0;
}

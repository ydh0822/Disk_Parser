#include "WorkerOutcomePolicy.h"

#include "ForensicImageExtractor/domain/ForensicOperationResultUtils.h"

namespace fie::workers::detail {

std::pair<std::vector<domain::FileEntry>, domain::ForensicOperationResult>
resolveDirectoryListOutcome(std::vector<domain::FileEntry> entries,
                            const QString &error,
                            bool cancellationObserved,
                            domain::ForensicBackend backend) {
  if (cancellationObserved) {
    return {{}, domain::op::cancelled(backend)};
  }
  if (!error.isEmpty()) {
    return {{}, domain::op::failure("directory_list_failed", error, backend)};
  }
  return {std::move(entries), domain::op::success(backend, "directory_listed", "Directory listed")};
}

std::pair<std::vector<domain::ArtifactRecord>, domain::ForensicOperationResult>
resolveArtifactDiscoveryOutcome(std::vector<domain::ArtifactRecord> artifacts,
                                const QStringList &warnings,
                                bool cancellationObserved,
                                domain::ForensicBackend backend) {
  if (cancellationObserved) {
    return {{}, domain::op::cancelled(backend)};
  }
  if (!warnings.isEmpty()) {
    return {std::move(artifacts),
            domain::op::successWithWarning(backend,
                                           "artifact_scan_with_warnings",
                                           "Artifact scan completed with warnings",
                                           domain::op::formatWarningDetail(warnings))};
  }
  return {std::move(artifacts),
          domain::op::success(backend, "artifact_scan_completed", "Artifact scan completed")};
}

std::pair<std::vector<domain::ExtractionResult>, domain::ForensicOperationResult>
resolveExtractionOutcome(std::vector<domain::ExtractionResult> results,
                         const QString &error,
                         bool cancellationObserved,
                         domain::ForensicBackend backend) {
  if (cancellationObserved) {
    return {{}, domain::op::cancelled(backend)};
  }

  if (!error.isEmpty()) {
    return {{}, domain::op::failure("extraction_failed", error, backend)};
  }

  bool hasWarnings = false;
  for (const auto &result : results) {
    if (!result.warning.isEmpty()) {
      hasWarnings = true;
      break;
    }
  }

  if (hasWarnings) {
    return {std::move(results),
            domain::op::successWithWarning(backend,
                                           "extraction_completed_with_warnings",
                                           "Extraction completed with warnings")};
  }

  return {std::move(results), domain::op::success(backend, "extraction_completed", "Extraction completed")};
}

} // namespace fie::workers::detail

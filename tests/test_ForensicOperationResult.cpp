#include "ForensicImageExtractor/domain/ForensicOperationResultUtils.h"

int runForensicOperationResultTests() {
  fie::domain::ForensicOperationResult success;
  success.state = fie::domain::ForensicOperationState::Success;
  success.backend = fie::domain::ForensicBackend::ReaderBridge;
  success.diagnostic.reason = "partition_enumerated";
  if (!success.succeeded() || success.hasWarning()) {
    return 1;
  }

  fie::domain::ForensicOperationResult warning;
  warning.state = fie::domain::ForensicOperationState::SuccessWithWarning;
  warning.backend = fie::domain::ForensicBackend::PathFallback;
  warning.diagnostic.reason = "partition_enumeration_with_fallback";
  warning.diagnostic.userMessage = "Partitions enumerated using fallback backend";
  if (!warning.succeeded() || !warning.hasWarning()) {
    return 1;
  }

  fie::domain::ForensicOperationResult failure;
  failure.state = fie::domain::ForensicOperationState::Failure;
  failure.backend = fie::domain::ForensicBackend::PathFallback;
  failure.diagnostic.reason = "filesystem_open_failed";
  failure.diagnostic.userMessage = "Filesystem open failed";
  failure.diagnostic.detail = "TSK error details";
  if (failure.succeeded() || failure.hasWarning()) {
    return 1;
  }

  fie::domain::ForensicOperationResult ambiguous;
  ambiguous.state = fie::domain::ForensicOperationState::Failure;
  ambiguous.backend = fie::domain::ForensicBackend::Unknown;
  ambiguous.diagnostic.reason = "tsk_image_open_failed";
  if (ambiguous.succeeded() || ambiguous.hasWarning()) {
    return 1;
  }

  const auto warnResult = fie::domain::op::successWithWarning(
      fie::domain::ForensicBackend::ReaderBridge,
      "artifact_scan_with_warnings",
      "Artifact scan completed with warnings",
      fie::domain::op::formatWarningDetail({"a", "b"}));
  if (!warnResult.succeeded() || !warnResult.hasWarning() || warnResult.diagnostic.detail != "a || b") {
    return 1;
  }

  return 0;
}

#pragma once

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"

namespace fie::domain::op {

// `diagnostic.detail` is opaque diagnostic text intended for logs and analyst context.
// Callers must not parse it as a stable structured protocol.
inline QString formatWarningDetail(const QStringList &warnings) {
  return warnings.join(" || ");
}

inline ForensicBackend backendFromOpenAdapter(const core::TskImageHandleAdapter &adapter) {
  if (!adapter.isOpen()) {
    return ForensicBackend::Unknown;
  }
  return adapter.backend() == core::TskOpenBackend::ReaderBridge ? ForensicBackend::ReaderBridge
                                                                  : ForensicBackend::PathFallback;
}

inline ForensicBackend backendForImageOpenFailure(const core::TskImageHandleAdapter &adapter) {
  if (!adapter.isPathFallbackEnabled()) {
    return ForensicBackend::ReaderBridge;
  }
  return ForensicBackend::Unknown;
}

inline ForensicOperationResult makeResult(ForensicOperationState state, ForensicBackend backend,
                                          const QString &reason, const QString &userMessage,
                                          const QString &detail = {}) {
  ForensicOperationResult out;
  out.state = state;
  out.backend = backend;
  out.diagnostic.reason = reason;
  out.diagnostic.userMessage = userMessage;
  out.diagnostic.detail = detail;
  return out;
}

inline ForensicOperationResult failure(const QString &reason, const QString &userMessage,
                                       ForensicBackend backend = ForensicBackend::NotApplicable,
                                       const QString &detail = {}) {
  return makeResult(ForensicOperationState::Failure, backend, reason, userMessage, detail);
}

inline ForensicOperationResult success(ForensicBackend backend, const QString &reason,
                                       const QString &userMessage, const QString &detail = {}) {
  return makeResult(ForensicOperationState::Success, backend, reason, userMessage, detail);
}

inline ForensicOperationResult successWithWarning(ForensicBackend backend, const QString &reason,
                                                  const QString &userMessage,
                                                  const QString &detail = {}) {
  return makeResult(ForensicOperationState::SuccessWithWarning, backend, reason, userMessage, detail);
}

inline ForensicOperationResult cancelled(ForensicBackend backend = ForensicBackend::NotApplicable,
                                         const QString &detail = {}) {
  return failure("cancelled", "Task cancelled", backend, detail);
}

} // namespace fie::domain::op

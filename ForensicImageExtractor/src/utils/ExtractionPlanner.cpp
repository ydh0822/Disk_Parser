#include "ForensicImageExtractor/utils/ExtractionPlanner.h"

#include "ForensicImageExtractor/utils/PathUtils.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSet>
#include <algorithm>

namespace fie::utils {

QString sanitizeLogicalPath(const QString &logicalPath) {
  const auto parts = logicalPath.split('/', Qt::SkipEmptyParts);
  QStringList clean;
  clean.reserve(parts.size());
  for (const auto &p : parts) {
    clean.push_back(sanitizePathComponent(p));
  }
  return clean.join('/');
}

QString composeDestinationPath(const QString &root, const QString &logicalPath) {
  return QDir(root).filePath(sanitizeLogicalPath(logicalPath));
}

static QString applyVersionSuffix(const QString &path, int version) {
  QFileInfo info(path);
  const QString base = info.completeBaseName();
  const QString ext = info.suffix();
  const QString candidateName = ext.isEmpty() ? QString("%1 (%2)").arg(base).arg(version)
                                               : QString("%1 (%2).%3").arg(base).arg(version).arg(ext);
  return QDir(info.path()).filePath(candidateName);
}

QString resolveDestinationPath(const QString &requestedPath, domain::OverwriteMode mode, QString &decisionStatus) {
  if (!QFile::exists(requestedPath)) {
    decisionStatus = "new";
    return requestedPath;
  }

  if (mode == domain::OverwriteMode::SkipExisting) {
    decisionStatus = "skipped_existing";
    return requestedPath;
  }

  if (mode == domain::OverwriteMode::Overwrite) {
    decisionStatus = "overwrite";
    return requestedPath;
  }

  decisionStatus = "versioned_copy";
  int version = 1;
  QString candidate = requestedPath;
  while (QFile::exists(candidate)) {
    candidate = applyVersionSuffix(requestedPath, version++);
  }
  return candidate;
}

std::vector<quint64> buildChunkPlan(quint64 totalSize, quint64 chunkSize) {
  std::vector<quint64> plan;
  if (chunkSize == 0) {
    return plan;
  }

  quint64 remaining = totalSize;
  while (remaining > 0) {
    const auto step = std::min(remaining, chunkSize);
    plan.push_back(step);
    remaining -= step;
  }
  if (totalSize == 0) {
    plan.push_back(0);
  }
  return plan;
}


QStringList deduplicateOrderedPaths(const QStringList &paths) {
  QSet<QString> seen;
  QStringList out;
  for (const auto &p : paths) {
    if (seen.contains(p)) continue;
    seen.insert(p);
    out.push_back(p);
  }
  return out;
}


QString successOutcomeFromDecision(const QString &decision) {
  if (decision == "overwrite") return "success_overwrite";
  if (decision == "versioned_copy") return "success_versioned";
  return "success";
}

QString finalStatusFromOutcome(const QString &primaryOutcome, bool hasWarning, bool hasError) {
  if (hasError) return primaryOutcome;
  if (hasWarning && primaryOutcome.startsWith("success")) return "success_with_warning";
  return primaryOutcome;
}

} // namespace fie::utils

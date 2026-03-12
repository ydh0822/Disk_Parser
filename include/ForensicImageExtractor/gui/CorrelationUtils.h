#pragma once

#include <QString>

namespace fie::gui {

inline bool pathsCorrelate(const QString &entryPath, const QString &artifactPath) {
  if (entryPath.isEmpty() || artifactPath.isEmpty()) return false;
  const bool exact = artifactPath.compare(entryPath, Qt::CaseInsensitive) == 0;
  const bool artifactContainsEntry = entryPath.startsWith(artifactPath + '/', Qt::CaseInsensitive);
  const bool entryContainsArtifact = artifactPath.startsWith(entryPath + '/', Qt::CaseInsensitive);
  return exact || artifactContainsEntry || entryContainsArtifact;
}

inline int pathCorrelationRank(const QString &entryPath, const QString &artifactPath) {
  if (entryPath.isEmpty() || artifactPath.isEmpty()) return 100;
  if (artifactPath.compare(entryPath, Qt::CaseInsensitive) == 0) return 0;
  if (entryPath.startsWith(artifactPath + '/', Qt::CaseInsensitive)) return 1;
  if (artifactPath.startsWith(entryPath + '/', Qt::CaseInsensitive)) return 2;
  return 100;
}

} // namespace fie::gui

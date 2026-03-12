#pragma once

#include <QString>

namespace fie::gui {

enum class PathCorrelationType {
  None,
  Exact,
  ArtifactAncestor,
  ArtifactDescendant,
};

struct PathCorrelation {
  PathCorrelationType type{PathCorrelationType::None};
  int rank{100};
  bool correlated() const { return type != PathCorrelationType::None; }
};

inline PathCorrelation pathCorrelation(const QString &entryPath, const QString &artifactPath) {
  if (entryPath.isEmpty() || artifactPath.isEmpty()) return {};
  if (artifactPath.compare(entryPath, Qt::CaseInsensitive) == 0) {
    return {PathCorrelationType::Exact, 0};
  }
  if (entryPath.startsWith(artifactPath + '/', Qt::CaseInsensitive)) {
    return {PathCorrelationType::ArtifactAncestor, 1};
  }
  if (artifactPath.startsWith(entryPath + '/', Qt::CaseInsensitive)) {
    return {PathCorrelationType::ArtifactDescendant, 2};
  }
  return {};
}

inline QString pathCorrelationTypeLabel(PathCorrelationType type) {
  switch (type) {
  case PathCorrelationType::Exact:
    return "exact path";
  case PathCorrelationType::ArtifactAncestor:
    return "artifact path is parent context";
  case PathCorrelationType::ArtifactDescendant:
    return "artifact path is child context";
  case PathCorrelationType::None:
  default:
    return "none";
  }
}

inline bool pathsCorrelate(const QString &entryPath, const QString &artifactPath) {
  return pathCorrelation(entryPath, artifactPath).correlated();
}

inline int pathCorrelationRank(const QString &entryPath, const QString &artifactPath) {
  return pathCorrelation(entryPath, artifactPath).rank;
}

} // namespace fie::gui

#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <optional>
#include <string>
#include <unordered_map>

namespace fie::gui {

inline QString artifactDetailCacheKey(const QString &partitionIdentifier, const QString &logicalPath) {
  return QString("%1|%2").arg(partitionIdentifier.trimmed().toLower(), logicalPath.trimmed().toLower());
}

inline QString artifactDetailCacheKey(const domain::ArtifactRecord &artifact) {
  return artifactDetailCacheKey(artifact.partitionIdentifier, artifact.sourceLogicalPath);
}

class ArtifactDetailSessionCache {
public:
  bool contains(const QString &key) const {
    return m_cache.find(key.toStdString()) != m_cache.end();
  }

  std::optional<std::optional<domain::ArtifactDetails>> get(const QString &key) const {
    const auto it = m_cache.find(key.toStdString());
    if (it == m_cache.end()) return std::nullopt;
    return it->second;
  }

  void put(const QString &key, std::optional<domain::ArtifactDetails> details) {
    m_cache[key.toStdString()] = std::move(details);
  }

  void clear() { m_cache.clear(); }

private:
  std::unordered_map<std::string, std::optional<domain::ArtifactDetails>> m_cache;
};

inline bool shouldApplyArtifactDetailResult(quint64 activeRequestId,
                                            const QString &activeKey,
                                            const QString &currentSelectionKey,
                                            quint64 resultRequestId,
                                            const QString &resultKey) {
  return activeRequestId != 0 && resultRequestId == activeRequestId &&
         resultKey.compare(activeKey, Qt::CaseInsensitive) == 0 &&
         resultKey.compare(currentSelectionKey, Qt::CaseInsensitive) == 0;
}

} // namespace fie::gui

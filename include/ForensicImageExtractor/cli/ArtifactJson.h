#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QJsonArray>
#include <QJsonObject>

#include <algorithm>
#include <vector>

namespace fie::cli {

inline QJsonObject artifactToJson(const domain::ArtifactRecord &artifact) {
  QJsonObject obj;
  obj["category"] = artifact.category;
  obj["artifact_name"] = artifact.artifactName;
  obj["profile"] = artifact.profile;
  obj["source_logical_path"] = artifact.sourceLogicalPath;
  obj["status"] = artifact.status;
  obj["directory_target"] = artifact.directoryTarget;
  obj["size_bytes"] = static_cast<qint64>(artifact.sizeBytes);
  obj["key_timestamp"] = artifact.keyTimestamp ? artifact.keyTimestamp->toString(Qt::ISODate) : QString();
  obj["partition_identifier"] = artifact.partitionIdentifier;
  obj["filesystem_type"] = artifact.fileSystemType;
  obj["notes"] = artifact.notes;
  return obj;
}

inline QJsonArray artifactsToJsonArray(std::vector<domain::ArtifactRecord> artifacts) {
  std::stable_sort(artifacts.begin(), artifacts.end(), [](const domain::ArtifactRecord &a, const domain::ArtifactRecord &b) {
    if (a.category.compare(b.category, Qt::CaseInsensitive) != 0) {
      return a.category.compare(b.category, Qt::CaseInsensitive) < 0;
    }
    if (a.artifactName.compare(b.artifactName, Qt::CaseInsensitive) != 0) {
      return a.artifactName.compare(b.artifactName, Qt::CaseInsensitive) < 0;
    }
    if (a.profile.compare(b.profile, Qt::CaseInsensitive) != 0) {
      return a.profile.compare(b.profile, Qt::CaseInsensitive) < 0;
    }
    return a.sourceLogicalPath.compare(b.sourceLogicalPath, Qt::CaseInsensitive) < 0;
  });

  QJsonArray rows;
  for (const auto &artifact : artifacts) {
    rows.append(artifactToJson(artifact));
  }
  return rows;
}

} // namespace fie::cli

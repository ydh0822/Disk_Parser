#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QJsonArray>
#include <QJsonObject>

#include <algorithm>
#include <vector>

namespace fie::cli {

inline QString parseStateToString(domain::ArtifactParseState state) {
  switch (state) {
  case domain::ArtifactParseState::Unsupported:
    return "unsupported";
  case domain::ArtifactParseState::Parsed:
    return "parsed";
  case domain::ArtifactParseState::Partial:
    return "partial";
  case domain::ArtifactParseState::Failed:
    return "failed";
  }
  return "unsupported";
}

inline QJsonObject artifactDetailsToJson(const domain::ArtifactDetails &details) {
  auto nullableString = [](const QString &value) -> QJsonValue {
    return value.isEmpty() ? QJsonValue::Null : QJsonValue(value);
  };
  auto nullableIsoTime = [](const std::optional<QDateTime> &value) -> QJsonValue {
    return value ? QJsonValue(value->toString(Qt::ISODate)) : QJsonValue::Null;
  };

  QJsonObject obj;
  obj["provider"] = details.provider;
  obj["state"] = parseStateToString(details.state);
  obj["summary"] = nullableString(details.summary);
  obj["error"] = nullableString(details.error);

  QJsonArray warnings;
  for (const auto &w : details.warnings) warnings.append(w);
  obj["warnings"] = warnings;

  obj["original_path"] = nullableString(details.originalPath);
  obj["deletion_timestamp"] = nullableIsoTime(details.deletionTimestamp);
  obj["original_size_bytes"] = details.originalSizeBytes ? QJsonValue(static_cast<qint64>(*details.originalSizeBytes))
                                                         : QJsonValue::Null;
  obj["target_path"] = nullableString(details.targetPath);
  obj["working_directory"] = nullableString(details.workingDirectory);
  obj["command_line_arguments"] = nullableString(details.commandLineArguments);
  obj["relative_path"] = nullableString(details.relativePath);
  obj["created_timestamp"] = nullableIsoTime(details.createdTimestamp);
  obj["modified_timestamp"] = nullableIsoTime(details.modifiedTimestamp);
  obj["accessed_timestamp"] = nullableIsoTime(details.accessedTimestamp);
  obj["executable_name"] = nullableString(details.executableName);
  obj["format_version"] = details.formatVersion ? QJsonValue(*details.formatVersion) : QJsonValue::Null;
  obj["run_count"] = details.runCount ? QJsonValue(static_cast<qint64>(*details.runCount)) : QJsonValue::Null;

  QJsonArray lastRuns;
  for (const auto &dt : details.lastRunTimestamps) {
    lastRuns.append(dt.toString(Qt::ISODate));
  }
  obj["last_run_timestamps"] = lastRuns;

  QJsonArray visits;
  for (const auto &visit : details.browserVisits) {
    QJsonObject row;
    row["timestamp"] = visit.timestamp ? QJsonValue(visit.timestamp->toString(Qt::ISODate)) : QJsonValue::Null;
    row["url"] = visit.url.isEmpty() ? QJsonValue::Null : QJsonValue(visit.url);
    row["title"] = visit.title.isEmpty() ? QJsonValue::Null : QJsonValue(visit.title);
    row["visit_count"] = visit.visitCount ? QJsonValue(static_cast<qint64>(*visit.visitCount)) : QJsonValue::Null;
    visits.append(row);
  }
  obj["browser_visits"] = visits;

  QJsonArray downloads;
  for (const auto &download : details.browserDownloads) {
    QJsonObject row;
    row["timestamp"] = download.timestamp ? QJsonValue(download.timestamp->toString(Qt::ISODate)) : QJsonValue::Null;
    row["url"] = download.url.isEmpty() ? QJsonValue::Null : QJsonValue(download.url);
    row["target_path"] = download.targetPath.isEmpty() ? QJsonValue::Null : QJsonValue(download.targetPath);
    downloads.append(row);
  }
  obj["browser_downloads"] = downloads;

  QJsonArray runMru;
  for (const auto &entry : details.registryRunMruEntries) {
    QJsonObject row;
    row["value_name"] = entry.valueName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.valueName);
    row["command"] = entry.command.isEmpty() ? QJsonValue::Null : QJsonValue(entry.command);
    row["mru_position"] = entry.mruPosition ? QJsonValue(*entry.mruPosition) : QJsonValue::Null;
    runMru.append(row);
  }
  obj["registry_run_mru_entries"] = runMru;

  QJsonArray typedPaths;
  for (const auto &entry : details.registryTypedPathEntries) {
    QJsonObject row;
    row["value_name"] = entry.valueName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.valueName);
    row["path"] = entry.path.isEmpty() ? QJsonValue::Null : QJsonValue(entry.path);
    typedPaths.append(row);
  }
  obj["registry_typed_path_entries"] = typedPaths;

  QJsonArray recentDocs;
  for (const auto &entry : details.registryRecentDocEntries) {
    QJsonObject row;
    row["value_name"] = entry.valueName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.valueName);
    row["document_name"] = entry.documentName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.documentName);
    row["extension_group"] = entry.extensionGroup.isEmpty() ? QJsonValue::Null : QJsonValue(entry.extensionGroup);
    row["mru_position"] = entry.mruPosition ? QJsonValue(*entry.mruPosition) : QJsonValue::Null;
    recentDocs.append(row);
  }
  obj["registry_recent_doc_entries"] = recentDocs;

  QJsonArray userAssist;
  for (const auto &entry : details.registryUserAssistEntries) {
    QJsonObject row;
    row["encoded_name"] = entry.encodedName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.encodedName);
    row["decoded_name"] = entry.decodedName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.decodedName);
    row["run_count"] = entry.runCount ? QJsonValue(static_cast<qint64>(*entry.runCount)) : QJsonValue::Null;
    row["last_execution"] = entry.lastExecution ? QJsonValue(entry.lastExecution->toString(Qt::ISODate)) : QJsonValue::Null;
    userAssist.append(row);
  }
  obj["registry_userassist_entries"] = userAssist;

  QJsonArray amcache;
  for (const auto &entry : details.amcacheEntries) {
    QJsonObject row;
    row["program_path"] = entry.programPath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.programPath);
    row["file_name"] = entry.fileName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.fileName);
    row["sha1"] = entry.sha1.isEmpty() ? QJsonValue::Null : QJsonValue(entry.sha1);
    row["publisher"] = entry.publisher.isEmpty() ? QJsonValue::Null : QJsonValue(entry.publisher);
    row["product_name"] = entry.productName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.productName);
    row["version"] = entry.version.isEmpty() ? QJsonValue::Null : QJsonValue(entry.version);
    row["first_seen_timestamp"] = entry.firstSeenTimestamp ? QJsonValue(entry.firstSeenTimestamp->toString(Qt::ISODate))
                                                           : QJsonValue::Null;
    row["install_timestamp"] = entry.installTimestamp ? QJsonValue(entry.installTimestamp->toString(Qt::ISODate))
                                                      : QJsonValue::Null;
    amcache.append(row);
  }
  obj["amcache_entries"] = amcache;

  QJsonArray bamDam;
  for (const auto &entry : details.bamDamEntries) {
    QJsonObject row;
    row["source"] = entry.source.isEmpty() ? QJsonValue::Null : QJsonValue(entry.source);
    row["sid"] = entry.sid.isEmpty() ? QJsonValue::Null : QJsonValue(entry.sid);
    row["executable_path"] = entry.executablePath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.executablePath);
    row["last_execution_timestamp"] = entry.lastExecutionTimestamp
                                          ? QJsonValue(entry.lastExecutionTimestamp->toString(Qt::ISODate))
                                          : QJsonValue::Null;
    bamDam.append(row);
  }
  obj["bam_dam_entries"] = bamDam;
  return obj;
}

inline QJsonObject artifactToJson(const domain::ArtifactRecord &artifact, bool includeDetails = false) {
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
  if (includeDetails) {
    obj["details"] = artifact.details ? artifactDetailsToJson(*artifact.details) : QJsonValue::Null;
  }
  return obj;
}

inline QJsonArray artifactsToJsonArray(std::vector<domain::ArtifactRecord> artifacts, bool includeDetails = false) {
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
    rows.append(artifactToJson(artifact, includeDetails));
  }
  return rows;
}

} // namespace fie::cli

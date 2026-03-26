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

  obj["appcompatcache_format"] = details.appCompatCacheFormat.isEmpty() ? QJsonValue::Null
                                                                         : QJsonValue(details.appCompatCacheFormat);
  QJsonArray appCompatCache;
  for (const auto &entry : details.appCompatCacheEntries) {
    QJsonObject row;
    row["source_registry_path"] = entry.sourceRegistryPath.isEmpty() ? QJsonValue::Null
                                                                      : QJsonValue(entry.sourceRegistryPath);
    row["entry_index"] = entry.entryIndex ? QJsonValue(*entry.entryIndex) : QJsonValue::Null;
    row["executable_path"] = entry.executablePath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.executablePath);
    row["last_modified_timestamp"] = entry.lastModifiedTimestamp
                                         ? QJsonValue(entry.lastModifiedTimestamp->toString(Qt::ISODate))
                                         : QJsonValue::Null;
    row["execution_flag"] = entry.executionFlag ? QJsonValue(*entry.executionFlag) : QJsonValue::Null;
    appCompatCache.append(row);
  }
  obj["appcompatcache_entries"] = appCompatCache;

  QJsonArray services;
  for (const auto &entry : details.serviceEntries) {
    QJsonObject row;
    row["service_name"] = entry.serviceName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.serviceName);
    row["source_registry_path"] = entry.sourceRegistryPath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.sourceRegistryPath);
    row["display_name"] = entry.displayName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.displayName);
    row["image_path"] = entry.imagePath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.imagePath);
    row["service_dll"] = entry.serviceDll.isEmpty() ? QJsonValue::Null : QJsonValue(entry.serviceDll);
    row["start_type"] = entry.startType ? QJsonValue(static_cast<qint64>(*entry.startType)) : QJsonValue::Null;
    row["service_type"] = entry.serviceType ? QJsonValue(static_cast<qint64>(*entry.serviceType)) : QJsonValue::Null;
    row["object_name"] = entry.objectName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.objectName);
    row["description"] = entry.description.isEmpty() ? QJsonValue::Null : QJsonValue(entry.description);
    row["delayed_auto_start"] = entry.delayedAutoStart ? QJsonValue(*entry.delayedAutoStart) : QJsonValue::Null;
    row["load_order_group"] = entry.loadOrderGroup.isEmpty() ? QJsonValue::Null : QJsonValue(entry.loadOrderGroup);
    QJsonArray deps;
    for (const auto &d : entry.dependencies) deps.append(d);
    row["dependencies"] = deps;
    row["key_last_write_timestamp"] = entry.keyLastWriteTimestamp
                                          ? QJsonValue(entry.keyLastWriteTimestamp->toString(Qt::ISODate))
                                          : QJsonValue::Null;
    services.append(row);
  }
  obj["service_entries"] = services;

  QJsonArray scheduledTasks;
  for (const auto &entry : details.scheduledTaskEntries) {
    QJsonObject row;
    row["task_name"] = entry.taskName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.taskName);
    row["task_path"] = entry.taskPath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.taskPath);
    row["uri"] = entry.uri.isEmpty() ? QJsonValue::Null : QJsonValue(entry.uri);
    row["author"] = entry.author.isEmpty() ? QJsonValue::Null : QJsonValue(entry.author);
    row["description"] = entry.description.isEmpty() ? QJsonValue::Null : QJsonValue(entry.description);
    row["command"] = entry.command.isEmpty() ? QJsonValue::Null : QJsonValue(entry.command);
    row["arguments"] = entry.arguments.isEmpty() ? QJsonValue::Null : QJsonValue(entry.arguments);
    row["working_directory"] = entry.workingDirectory.isEmpty() ? QJsonValue::Null : QJsonValue(entry.workingDirectory);
    row["enabled"] = entry.enabled ? QJsonValue(*entry.enabled) : QJsonValue::Null;
    row["hidden"] = entry.hidden ? QJsonValue(*entry.hidden) : QJsonValue::Null;
    row["run_level"] = entry.runLevel.isEmpty() ? QJsonValue::Null : QJsonValue(entry.runLevel);
    row["user_id"] = entry.userId.isEmpty() ? QJsonValue::Null : QJsonValue(entry.userId);
    row["logon_type"] = entry.logonType.isEmpty() ? QJsonValue::Null : QJsonValue(entry.logonType);
    QJsonArray triggers;
    for (const auto &t : entry.triggerSummaries) triggers.append(t);
    row["trigger_summaries"] = triggers;
    row["repetition_summary"] = entry.repetitionSummary.isEmpty() ? QJsonValue::Null : QJsonValue(entry.repetitionSummary);
    row["action_type"] = entry.actionType.isEmpty() ? QJsonValue::Null : QJsonValue(entry.actionType);
    row["registration_date"] = entry.registrationDate ? QJsonValue(entry.registrationDate->toString(Qt::ISODate)) : QJsonValue::Null;
    scheduledTasks.append(row);
  }
  obj["scheduled_task_entries"] = scheduledTasks;

  QJsonArray werReports;
  for (const auto &entry : details.werReportEntries) {
    QJsonObject row;
    row["report_path"] = entry.reportPath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.reportPath);
    row["report_name"] = entry.reportName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.reportName);
    row["event_type"] = entry.eventType.isEmpty() ? QJsonValue::Null : QJsonValue(entry.eventType);
    row["application_name"] = entry.applicationName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.applicationName);
    row["application_path"] = entry.applicationPath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.applicationPath);
    row["fault_module_name"] = entry.faultModuleName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.faultModuleName);
    row["fault_module_path"] = entry.faultModulePath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.faultModulePath);
    row["exception_code"] = entry.exceptionCode.isEmpty() ? QJsonValue::Null : QJsonValue(entry.exceptionCode);
    row["bucket_id"] = entry.bucketId.isEmpty() ? QJsonValue::Null : QJsonValue(entry.bucketId);
    row["cab_id"] = entry.cabId.isEmpty() ? QJsonValue::Null : QJsonValue(entry.cabId);
    row["report_id"] = entry.reportId.isEmpty() ? QJsonValue::Null : QJsonValue(entry.reportId);
    row["response"] = entry.response.isEmpty() ? QJsonValue::Null : QJsonValue(entry.response);
    QJsonArray sigs;
    for (const auto &s : entry.problemSignatures) sigs.append(s);
    row["problem_signatures"] = sigs;
    row["report_timestamp"] = entry.reportTimestamp ? QJsonValue(entry.reportTimestamp->toString(Qt::ISODate))
                                                    : QJsonValue::Null;
    werReports.append(row);
  }
  obj["wer_report_entries"] = werReports;

  QJsonArray usbDevices;
  for (const auto &entry : details.usbDeviceEntries) {
    QJsonObject row;
    row["device_class"] = entry.deviceClass.isEmpty() ? QJsonValue::Null : QJsonValue(entry.deviceClass);
    row["enum_root"] = entry.enumRoot.isEmpty() ? QJsonValue::Null : QJsonValue(entry.enumRoot);
    row["device_identifier"] = entry.deviceIdentifier.isEmpty() ? QJsonValue::Null : QJsonValue(entry.deviceIdentifier);
    row["instance_id"] = entry.instanceId.isEmpty() ? QJsonValue::Null : QJsonValue(entry.instanceId);
    row["vendor"] = entry.vendor.isEmpty() ? QJsonValue::Null : QJsonValue(entry.vendor);
    row["product"] = entry.product.isEmpty() ? QJsonValue::Null : QJsonValue(entry.product);
    row["revision"] = entry.revision.isEmpty() ? QJsonValue::Null : QJsonValue(entry.revision);
    row["serial_number"] = entry.serialNumber.isEmpty() ? QJsonValue::Null : QJsonValue(entry.serialNumber);
    row["friendly_name"] = entry.friendlyName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.friendlyName);
    row["parent_id_prefix"] = entry.parentIdPrefix.isEmpty() ? QJsonValue::Null : QJsonValue(entry.parentIdPrefix);
    row["service"] = entry.service.isEmpty() ? QJsonValue::Null : QJsonValue(entry.service);
    row["class_guid"] = entry.classGuid.isEmpty() ? QJsonValue::Null : QJsonValue(entry.classGuid);
    row["source_registry_path"] = entry.sourceRegistryPath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.sourceRegistryPath);
    row["key_last_write_timestamp"] = entry.keyLastWriteTimestamp
                                          ? QJsonValue(entry.keyLastWriteTimestamp->toString(Qt::ISODate))
                                          : QJsonValue::Null;
    usbDevices.append(row);
  }
  obj["usb_device_entries"] = usbDevices;

  QJsonArray evtxLogs;
  for (const auto &log : details.evtxLogEntries) {
    QJsonObject row;
    row["log_name"] = log.logName.isEmpty() ? QJsonValue::Null : QJsonValue(log.logName);
    row["file_path"] = log.filePath.isEmpty() ? QJsonValue::Null : QJsonValue(log.filePath);
    row["record_count"] = log.recordCount ? QJsonValue(*log.recordCount) : QJsonValue::Null;
    row["first_event_timestamp"] =
        log.firstEventTimestamp ? QJsonValue(log.firstEventTimestamp->toString(Qt::ISODate)) : QJsonValue::Null;
    row["last_event_timestamp"] =
        log.lastEventTimestamp ? QJsonValue(log.lastEventTimestamp->toString(Qt::ISODate)) : QJsonValue::Null;
    QJsonArray events;
    for (const auto &entry : log.events) {
      QJsonObject event;
      event["record_id"] = entry.recordId ? QJsonValue(static_cast<qint64>(*entry.recordId)) : QJsonValue::Null;
      event["timestamp"] = entry.timestamp ? QJsonValue(entry.timestamp->toString(Qt::ISODate)) : QJsonValue::Null;
      event["provider_name"] = entry.providerName.isEmpty() ? QJsonValue::Null : QJsonValue(entry.providerName);
      event["event_id"] = entry.eventId ? QJsonValue(*entry.eventId) : QJsonValue::Null;
      event["level"] = entry.level ? QJsonValue(*entry.level) : QJsonValue::Null;
      event["computer"] = entry.computer.isEmpty() ? QJsonValue::Null : QJsonValue(entry.computer);
      event["opcode"] = entry.opcode ? QJsonValue(*entry.opcode) : QJsonValue::Null;
      event["task"] = entry.task ? QJsonValue(*entry.task) : QJsonValue::Null;
      event["keywords"] = entry.keywords.isEmpty() ? QJsonValue::Null : QJsonValue(entry.keywords);
      QJsonArray eventData;
      for (const auto &d : entry.eventData) eventData.append(d);
      event["event_data"] = eventData;
      events.append(event);
    }
    row["events"] = events;
    evtxLogs.append(row);
  }
  obj["evtx_log_entries"] = evtxLogs;

  obj["jump_list_format"] = details.jumpListFormat.isEmpty() ? QJsonValue::Null : QJsonValue(details.jumpListFormat);
  obj["jump_list_version"] = details.jumpListVersion ? QJsonValue(*details.jumpListVersion) : QJsonValue::Null;
  obj["jump_list_reported_entry_count"] = details.jumpListReportedEntryCount
                                              ? QJsonValue(static_cast<qint64>(*details.jumpListReportedEntryCount))
                                              : QJsonValue::Null;
  QJsonArray jumpListEntries;
  for (const auto &entry : details.jumpListEntries) {
    QJsonObject row;
    row["entry_identifier"] = entry.entryIdentifier.isEmpty() ? QJsonValue::Null : QJsonValue(entry.entryIdentifier);
    row["stream_number"] = entry.streamNumber ? QJsonValue(static_cast<qint64>(*entry.streamNumber)) : QJsonValue::Null;
    row["target_path"] = entry.targetPath.isEmpty() ? QJsonValue::Null : QJsonValue(entry.targetPath);
    row["target_summary"] = entry.targetSummary.isEmpty() ? QJsonValue::Null : QJsonValue(entry.targetSummary);
    row["last_access_timestamp"] = entry.lastAccessTimestamp ? QJsonValue(entry.lastAccessTimestamp->toString(Qt::ISODate))
                                                             : QJsonValue::Null;
    row["access_count"] = entry.accessCount ? QJsonValue(static_cast<qint64>(*entry.accessCount)) : QJsonValue::Null;
    row["pinned"] = entry.pinned ? QJsonValue(*entry.pinned) : QJsonValue::Null;
    jumpListEntries.append(row);
  }
  obj["jump_list_entries"] = jumpListEntries;
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

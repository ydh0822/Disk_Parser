#include "ForensicImageExtractor/forensics/ArtifactTimelineService.h"

#include <QMap>
#include <algorithm>

namespace fie::forensics {
namespace {

QString parseStateString(domain::ArtifactParseState state) {
  switch (state) {
  case domain::ArtifactParseState::Unsupported: return "unsupported";
  case domain::ArtifactParseState::Parsed: return "parsed";
  case domain::ArtifactParseState::Partial: return "partial";
  case domain::ArtifactParseState::Failed: return "failed";
  }
  return "unsupported";
}

domain::ArtifactEventRecord makeBaseEvent(const domain::ArtifactRecord &artifact,
                                          const domain::ArtifactDetails &details,
                                          const QString &eventType) {
  domain::ArtifactEventRecord event;
  event.eventType = eventType;
  event.category = artifact.category;
  event.artifactName = artifact.artifactName;
  event.profile = artifact.profile;
  event.sourceLogicalPath = artifact.sourceLogicalPath;
  event.partitionIdentifier = artifact.partitionIdentifier;
  event.fileSystemType = artifact.fileSystemType;
  event.parserProvider = details.provider;
  event.parseState = details.state;
  event.summary = details.summary;
  event.note = details.warnings.join(" | ");
  return event;
}

void addField(domain::ArtifactEventRecord &event, const QString &key, const std::optional<QString> &value) {
  event.fields.push_back({key, value});
}

std::optional<QString> asString(const QString &value) {
  if (value.isEmpty()) return std::nullopt;
  return value;
}

std::optional<QString> asNumberString(const std::optional<quint64> &value) {
  return value ? std::optional<QString>(QString::number(*value)) : std::nullopt;
}

std::optional<QString> asNumberString32(const std::optional<quint32> &value) {
  return value ? std::optional<QString>(QString::number(*value)) : std::nullopt;
}

void appendRecycleBinEvents(std::vector<domain::ArtifactEventRecord> &out,
                            const domain::ArtifactRecord &artifact,
                            const domain::ArtifactDetails &details) {
  if (!details.deletionTimestamp.has_value() && details.originalPath.isEmpty() && !details.originalSizeBytes.has_value()) {
    return;
  }

  auto event = makeBaseEvent(artifact, details, "recycle_bin_deletion");
  event.timestamp = details.deletionTimestamp;
  addField(event, "original_path", asString(details.originalPath));
  addField(event, "original_size_bytes", asNumberString(details.originalSizeBytes));
  out.push_back(std::move(event));
}

void appendLnkEvents(std::vector<domain::ArtifactEventRecord> &out,
                     const domain::ArtifactRecord &artifact,
                     const domain::ArtifactDetails &details) {
  const auto addLnkEvent = [&](const QString &eventType, const std::optional<QDateTime> &timestamp) {
    if (!timestamp.has_value()) return;
    auto event = makeBaseEvent(artifact, details, eventType);
    event.timestamp = timestamp;
    addField(event, "target_path", asString(details.targetPath));
    addField(event, "relative_path", asString(details.relativePath));
    addField(event, "working_directory", asString(details.workingDirectory));
    addField(event, "arguments", asString(details.commandLineArguments));
    out.push_back(std::move(event));
  };

  addLnkEvent("lnk_created", details.createdTimestamp);
  addLnkEvent("lnk_modified", details.modifiedTimestamp);
  addLnkEvent("lnk_accessed", details.accessedTimestamp);
}

void appendPrefetchEvents(std::vector<domain::ArtifactEventRecord> &out,
                          const domain::ArtifactRecord &artifact,
                          const domain::ArtifactDetails &details) {
  for (const auto &runTs : details.lastRunTimestamps) {
    auto event = makeBaseEvent(artifact, details, "prefetch_last_run");
    event.timestamp = runTs;
    addField(event, "executable_name", asString(details.executableName));
    addField(event, "run_count", asNumberString32(details.runCount));
    out.push_back(std::move(event));
  }

  if (details.lastRunTimestamps.empty() && (!details.executableName.isEmpty() || details.runCount.has_value())) {
    auto event = makeBaseEvent(artifact, details, "prefetch_observed");
    addField(event, "executable_name", asString(details.executableName));
    addField(event, "run_count", asNumberString32(details.runCount));
    out.push_back(std::move(event));
  }
}

void appendParseStatusEvent(std::vector<domain::ArtifactEventRecord> &out,
                            const domain::ArtifactRecord &artifact,
                            const domain::ArtifactDetails &details) {
  if (details.state != domain::ArtifactParseState::Failed && details.state != domain::ArtifactParseState::Partial) {
    return;
  }
  auto event = makeBaseEvent(artifact, details, "artifact_parse_status");
  event.note = details.error.isEmpty() ? details.warnings.join(" | ") : details.error;
  addField(event, "parse_state", parseStateString(details.state));
  out.push_back(std::move(event));
}

void appendBrowserEvents(std::vector<domain::ArtifactEventRecord> &out,
                         const domain::ArtifactRecord &artifact,
                         const domain::ArtifactDetails &details) {
  for (const auto &visit : details.browserVisits) {
    auto event = makeBaseEvent(artifact, details, "browser_visit");
    event.timestamp = visit.timestamp;
    addField(event, "url", asString(visit.url));
    addField(event, "title", asString(visit.title));
    addField(event, "visit_count",
             visit.visitCount ? std::optional<QString>(QString::number(*visit.visitCount)) : std::nullopt);
    out.push_back(std::move(event));
  }

  for (const auto &download : details.browserDownloads) {
    auto event = makeBaseEvent(artifact, details,
                               download.timestamp.has_value() ? "browser_download" : "browser_download_observed");
    event.timestamp = download.timestamp;
    addField(event, "download_url", asString(download.url));
    addField(event, "target_path", asString(download.targetPath));
    out.push_back(std::move(event));
  }
}

void appendRegistryEvents(std::vector<domain::ArtifactEventRecord> &out,
                          const domain::ArtifactRecord &artifact,
                          const domain::ArtifactDetails &details) {
  for (const auto &entry : details.registryRunMruEntries) {
    auto event = makeBaseEvent(artifact, details, "registry_run_mru");
    addField(event, "value_name", asString(entry.valueName));
    addField(event, "command", asString(entry.command));
    addField(event, "mru_position",
             entry.mruPosition ? std::optional<QString>(QString::number(*entry.mruPosition)) : std::nullopt);
    out.push_back(std::move(event));
  }
  for (const auto &entry : details.registryTypedPathEntries) {
    auto event = makeBaseEvent(artifact, details, "registry_typed_path");
    addField(event, "value_name", asString(entry.valueName));
    addField(event, "typed_path", asString(entry.path));
    out.push_back(std::move(event));
  }
  for (const auto &entry : details.registryRecentDocEntries) {
    auto event = makeBaseEvent(artifact, details, "registry_recent_doc");
    addField(event, "value_name", asString(entry.valueName));
    addField(event, "document_name", asString(entry.documentName));
    addField(event, "extension_group", asString(entry.extensionGroup));
    addField(event, "mru_position",
             entry.mruPosition ? std::optional<QString>(QString::number(*entry.mruPosition)) : std::nullopt);
    out.push_back(std::move(event));
  }
  for (const auto &entry : details.registryUserAssistEntries) {
    auto event = makeBaseEvent(artifact, details, "userassist_execution");
    event.timestamp = entry.lastExecution;
    addField(event, "encoded_name", asString(entry.encodedName));
    addField(event, "decoded_name", asString(entry.decodedName));
    addField(event, "run_count", entry.runCount ? std::optional<QString>(QString::number(*entry.runCount)) : std::nullopt);
    out.push_back(std::move(event));
  }
}

void appendSystemExecutionEvents(std::vector<domain::ArtifactEventRecord> &out,
                                 const domain::ArtifactRecord &artifact,
                                 const domain::ArtifactDetails &details) {
  for (const auto &entry : details.amcacheEntries) {
    auto event = makeBaseEvent(artifact, details, "amcache_entry");
    event.timestamp = entry.firstSeenTimestamp;
    addField(event, "program_path", asString(entry.programPath));
    addField(event, "file_name", asString(entry.fileName));
    addField(event, "sha1", asString(entry.sha1));
    addField(event, "publisher", asString(entry.publisher));
    addField(event, "product_name", asString(entry.productName));
    addField(event, "version", asString(entry.version));
    addField(event, "install_timestamp",
             entry.installTimestamp ? std::optional<QString>(entry.installTimestamp->toString(Qt::ISODate)) : std::nullopt);
    out.push_back(std::move(event));
  }
  for (const auto &entry : details.bamDamEntries) {
    auto event = makeBaseEvent(artifact, details, entry.source.compare("dam", Qt::CaseInsensitive) == 0
                                                     ? "dam_execution"
                                                     : "bam_execution");
    event.timestamp = entry.lastExecutionTimestamp;
    addField(event, "sid", asString(entry.sid));
    addField(event, "executable_path", asString(entry.executablePath));
    out.push_back(std::move(event));
  }
}

void appendJumpListEvents(std::vector<domain::ArtifactEventRecord> &out,
                          const domain::ArtifactRecord &artifact,
                          const domain::ArtifactDetails &details) {
  for (const auto &entry : details.jumpListEntries) {
    auto event = makeBaseEvent(artifact, details,
                               entry.lastAccessTimestamp.has_value() ? "jump_list_access"
                                                                     : "jump_list_entry_observed");
    event.timestamp = entry.lastAccessTimestamp;
    addField(event, "entry_identifier", asString(entry.entryIdentifier));
    addField(event, "stream_number",
             entry.streamNumber ? std::optional<QString>(QString::number(*entry.streamNumber)) : std::nullopt);
    addField(event, "target_path", asString(entry.targetPath));
    addField(event, "target_summary", asString(entry.targetSummary));
    addField(event, "access_count",
             entry.accessCount ? std::optional<QString>(QString::number(*entry.accessCount)) : std::nullopt);
    addField(event, "pinned",
             entry.pinned ? std::optional<QString>(*entry.pinned ? "true" : "false") : std::nullopt);
    out.push_back(std::move(event));
  }
}

void appendAppCompatCacheEvents(std::vector<domain::ArtifactEventRecord> &out,
                                const domain::ArtifactRecord &artifact,
                                const domain::ArtifactDetails &details) {
  for (const auto &entry : details.appCompatCacheEntries) {
    auto event = makeBaseEvent(artifact, details,
                               entry.lastModifiedTimestamp.has_value() ? "appcompatcache_entry"
                                                                       : "appcompatcache_entry_observed");
    event.timestamp = entry.lastModifiedTimestamp;
    addField(event, "source_registry_path", asString(entry.sourceRegistryPath));
    addField(event, "entry_index",
             entry.entryIndex ? std::optional<QString>(QString::number(*entry.entryIndex)) : std::nullopt);
    addField(event, "executable_path", asString(entry.executablePath));
    addField(event, "execution_flag",
             entry.executionFlag ? std::optional<QString>(*entry.executionFlag ? "true" : "false") : std::nullopt);
    out.push_back(std::move(event));
  }
}

void appendServiceEvents(std::vector<domain::ArtifactEventRecord> &out,
                         const domain::ArtifactRecord &artifact,
                         const domain::ArtifactDetails &details) {
  for (const auto &entry : details.serviceEntries) {
    auto event = makeBaseEvent(artifact, details,
                               entry.keyLastWriteTimestamp.has_value() ? "service_config_modified"
                                                                        : "service_config_observed");
    event.timestamp = entry.keyLastWriteTimestamp;
    addField(event, "service_name", asString(entry.serviceName));
    addField(event, "display_name", asString(entry.displayName));
    addField(event, "image_path", asString(entry.imagePath));
    addField(event, "service_dll", asString(entry.serviceDll));
    addField(event, "source_registry_path", asString(entry.sourceRegistryPath));
    addField(event, "start_type",
             entry.startType ? std::optional<QString>(QString::number(*entry.startType)) : std::nullopt);
    addField(event, "service_type",
             entry.serviceType ? std::optional<QString>(QString::number(*entry.serviceType)) : std::nullopt);
    out.push_back(std::move(event));
  }
}

void appendScheduledTaskEvents(std::vector<domain::ArtifactEventRecord> &out,
                               const domain::ArtifactRecord &artifact,
                               const domain::ArtifactDetails &details) {
  for (const auto &entry : details.scheduledTaskEntries) {
    auto event = makeBaseEvent(artifact, details,
                               entry.registrationDate.has_value() ? "scheduled_task_registered"
                                                                  : "scheduled_task_observed");
    event.timestamp = entry.registrationDate;
    addField(event, "task_name", asString(entry.taskName));
    addField(event, "task_path", asString(entry.taskPath));
    addField(event, "uri", asString(entry.uri));
    addField(event, "author", asString(entry.author));
    addField(event, "command", asString(entry.command));
    addField(event, "arguments", asString(entry.arguments));
    addField(event, "action_type", asString(entry.actionType));
    out.push_back(std::move(event));
  }
}

void appendWerEvents(std::vector<domain::ArtifactEventRecord> &out,
                     const domain::ArtifactRecord &artifact,
                     const domain::ArtifactDetails &details) {
  for (const auto &entry : details.werReportEntries) {
    auto event = makeBaseEvent(artifact, details,
                               entry.reportTimestamp.has_value() ? "wer_report_created" : "wer_report_observed");
    event.timestamp = entry.reportTimestamp;
    addField(event, "report_name", asString(entry.reportName));
    addField(event, "report_path", asString(entry.reportPath));
    addField(event, "event_type", asString(entry.eventType));
    addField(event, "application_name", asString(entry.applicationName));
    addField(event, "fault_module_name", asString(entry.faultModuleName));
    addField(event, "exception_code", asString(entry.exceptionCode));
    addField(event, "bucket_id", asString(entry.bucketId));
    addField(event, "report_id", asString(entry.reportId));
    out.push_back(std::move(event));
  }
}

void appendUsbEvents(std::vector<domain::ArtifactEventRecord> &out,
                     const domain::ArtifactRecord &artifact,
                     const domain::ArtifactDetails &details) {
  for (const auto &entry : details.usbDeviceEntries) {
    auto event = makeBaseEvent(artifact, details,
                               entry.keyLastWriteTimestamp.has_value() ? "usb_device_registry_modified"
                                                                        : "usb_device_observed");
    event.timestamp = entry.keyLastWriteTimestamp;
    addField(event, "device_class", asString(entry.deviceClass));
    addField(event, "device_identifier", asString(entry.deviceIdentifier));
    addField(event, "instance_id", asString(entry.instanceId));
    addField(event, "serial_number", asString(entry.serialNumber));
    addField(event, "vendor", asString(entry.vendor));
    addField(event, "product", asString(entry.product));
    addField(event, "source_registry_path", asString(entry.sourceRegistryPath));
    out.push_back(std::move(event));
  }
}

void appendEvtxEvents(std::vector<domain::ArtifactEventRecord> &out,
                      const domain::ArtifactRecord &artifact,
                      const domain::ArtifactDetails &details) {
  auto isSysmonChannel = [](const QString &logName) {
    return logName.compare("Microsoft-Windows-Sysmon/Operational.evtx", Qt::CaseInsensitive) == 0;
  };
  auto isSysmonProvider = [](const QString &providerName) {
    return providerName.compare("Microsoft-Windows-Sysmon", Qt::CaseInsensitive) == 0;
  };
  auto parseEventDataMap = [](const QStringList &items) {
    QMap<QString, QString> kv;
    for (const auto &item : items) {
      const int eq = item.indexOf('=');
      if (eq <= 0) continue;
      const QString key = item.left(eq).trimmed();
      const QString value = item.mid(eq + 1).trimmed();
      if (key.isEmpty()) continue;
      kv.insert(key, value);
    }
    return kv;
  };
  auto sysmonTypeForEventId = [](quint32 eventId) -> QString {
    switch (eventId) {
    case 1: return "sysmon_process_create";
    case 3: return "sysmon_network_connect";
    case 4: return "sysmon_service_state_change";
    case 7: return "sysmon_image_load";
    case 8: return "sysmon_remote_thread";
    case 10: return "sysmon_process_access";
    case 11: return "sysmon_file_create";
    case 12:
    case 13:
    case 14: return "sysmon_registry_event";
    case 16: return "sysmon_config_change";
    case 17:
    case 18: return "sysmon_named_pipe";
    case 19:
    case 20:
    case 21: return "sysmon_wmi_event";
    case 22: return "sysmon_dns_query";
    case 25: return "sysmon_process_tampering";
    default: return {};
    }
  };

  for (const auto &log : details.evtxLogEntries) {
    for (const auto &entry : log.events) {
      auto event = makeBaseEvent(artifact, details, "evtx_event");
      event.timestamp = entry.timestamp;
      addField(event, "log_name", asString(log.logName));
      addField(event, "file_path", asString(log.filePath));
      addField(event, "record_id",
               entry.recordId ? std::optional<QString>(QString::number(*entry.recordId)) : std::nullopt);
      addField(event, "provider_name", asString(entry.providerName));
      addField(event, "event_id",
               entry.eventId ? std::optional<QString>(QString::number(*entry.eventId)) : std::nullopt);
      addField(event, "level", entry.level ? std::optional<QString>(QString::number(*entry.level)) : std::nullopt);
      addField(event, "computer", asString(entry.computer));
      out.push_back(std::move(event));

      if (!isSysmonChannel(log.logName) || !isSysmonProvider(entry.providerName) || !entry.eventId.has_value()) continue;
      const QString sysmonType = sysmonTypeForEventId(*entry.eventId);
      if (sysmonType.isEmpty()) continue;

      const auto data = parseEventDataMap(entry.eventData);
      auto sysmon = makeBaseEvent(artifact, details, sysmonType);
      sysmon.timestamp = entry.timestamp;
      addField(sysmon, "log_name", asString(log.logName));
      addField(sysmon, "event_id", QString::number(*entry.eventId));
      addField(sysmon, "rule_name", asString(data.value("RuleName")));
      addField(sysmon, "process_guid", asString(data.value("ProcessGuid")));
      addField(sysmon, "parent_process_guid", asString(data.value("ParentProcessGuid")));
      addField(sysmon, "process_id", asString(data.value("ProcessId")));
      addField(sysmon, "parent_process_id", asString(data.value("ParentProcessId")));
      addField(sysmon, "image", asString(data.value("Image")));
      addField(sysmon, "parent_image", asString(data.value("ParentImage")));
      addField(sysmon, "command_line", asString(data.value("CommandLine")));
      addField(sysmon, "parent_command_line", asString(data.value("ParentCommandLine")));
      addField(sysmon, "current_directory", asString(data.value("CurrentDirectory")));
      addField(sysmon, "user", asString(data.value("User")));
      addField(sysmon, "logon_guid", asString(data.value("LogonGuid")));
      addField(sysmon, "logon_id", asString(data.value("LogonId")));
      addField(sysmon, "hashes", asString(data.value("Hashes")));
      addField(sysmon, "source_ip", asString(data.value("SourceIp")));
      addField(sysmon, "destination_ip", asString(data.value("DestinationIp")));
      addField(sysmon, "destination_port", asString(data.value("DestinationPort")));
      addField(sysmon, "protocol", asString(data.value("Protocol")));
      addField(sysmon, "initiated", asString(data.value("Initiated")));
      addField(sysmon, "query_name", asString(data.value("QueryName")));
      addField(sysmon, "query_status", asString(data.value("QueryStatus")));
      addField(sysmon, "query_results", asString(data.value("QueryResults")));
      addField(sysmon, "target_filename", asString(data.value("TargetFilename")));
      addField(sysmon, "target_object", asString(data.value("TargetObject")));
      addField(sysmon, "details", asString(data.value("Details")));
      addField(sysmon, "pipe_name", asString(data.value("PipeName")));
      addField(sysmon, "source_image", asString(data.value("SourceImage")));
      addField(sysmon, "target_image", asString(data.value("TargetImage")));
      addField(sysmon, "granted_access", asString(data.value("GrantedAccess")));
      addField(sysmon, "call_trace", asString(data.value("CallTrace")));
      addField(sysmon, "start_module", asString(data.value("StartModule")));
      addField(sysmon, "start_function", asString(data.value("StartFunction")));
      addField(sysmon, "configuration", asString(data.value("Configuration")));
      addField(sysmon, "state", asString(data.value("State")));
      addField(sysmon, "version", asString(data.value("Version")));
      out.push_back(std::move(sysmon));
    }
  }
}

bool eventLess(const domain::ArtifactEventRecord &a, const domain::ArtifactEventRecord &b) {
  if (a.timestamp.has_value() != b.timestamp.has_value()) {
    return a.timestamp.has_value();
  }
  if (a.timestamp.has_value() && b.timestamp.has_value() && a.timestamp.value() != b.timestamp.value()) {
    return a.timestamp.value() < b.timestamp.value();
  }
  if (a.eventType.compare(b.eventType, Qt::CaseInsensitive) != 0) {
    return a.eventType.compare(b.eventType, Qt::CaseInsensitive) < 0;
  }
  if (a.sourceLogicalPath.compare(b.sourceLogicalPath, Qt::CaseInsensitive) != 0) {
    return a.sourceLogicalPath.compare(b.sourceLogicalPath, Qt::CaseInsensitive) < 0;
  }
  return a.profile.compare(b.profile, Qt::CaseInsensitive) < 0;
}

} // namespace

std::vector<domain::ArtifactEventRecord> ArtifactTimelineService::buildEvents(
    const std::vector<domain::ArtifactRecord> &artifacts) const {
  std::vector<domain::ArtifactEventRecord> events;

  for (const auto &artifact : artifacts) {
    if (!artifact.details.has_value()) continue;
    const auto &details = *artifact.details;

    if (details.provider == "windows.recycle_bin_i") {
      appendRecycleBinEvents(events, artifact, details);
    } else if (details.provider == "windows.lnk_summary") {
      appendLnkEvents(events, artifact, details);
    } else if (details.provider == "windows.prefetch_summary") {
      appendPrefetchEvents(events, artifact, details);
    } else if (details.provider == "windows.chromium_history") {
      appendBrowserEvents(events, artifact, details);
    } else if (details.provider == "windows.amcache" || details.provider == "windows.bam_dam") {
      appendSystemExecutionEvents(events, artifact, details);
    } else if (details.provider == "windows.appcompatcache_v1") {
      appendAppCompatCacheEvents(events, artifact, details);
    } else if (details.provider == "windows.services_v1") {
      appendServiceEvents(events, artifact, details);
    } else if (details.provider == "windows.scheduled_task_v1") {
      appendScheduledTaskEvents(events, artifact, details);
    } else if (details.provider == "windows.wer_v1") {
      appendWerEvents(events, artifact, details);
    } else if (details.provider == "windows.usb_registry_v1") {
      appendUsbEvents(events, artifact, details);
    } else if (details.provider == "windows.evtx_v1") {
      appendEvtxEvents(events, artifact, details);
    } else if (details.provider == "windows.jump_list_v1") {
      appendJumpListEvents(events, artifact, details);
    } else if (details.provider.startsWith("windows.registry_", Qt::CaseInsensitive)) {
      appendRegistryEvents(events, artifact, details);
    }
    appendParseStatusEvent(events, artifact, details);
  }

  std::stable_sort(events.begin(), events.end(), eventLess);
  return events;
}

} // namespace fie::forensics

#include "ForensicImageExtractor/forensics/ArtifactTimelineService.h"

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
    } else if (details.provider.startsWith("windows.registry_", Qt::CaseInsensitive)) {
      appendRegistryEvents(events, artifact, details);
    }
    appendParseStatusEvent(events, artifact, details);
  }

  std::stable_sort(events.begin(), events.end(), eventLess);
  return events;
}

} // namespace fie::forensics

#include "ForensicImageExtractor/cli/ArtifactJson.h"

#include <QJsonArray>
#include <QJsonObject>

int runCliArtifactJsonTests() {
  fie::domain::ArtifactRecord b;
  b.category = "Execution";
  b.artifactName = "Prefetch";
  b.profile = "SYSTEM";
  b.sourceLogicalPath = "/Windows/Prefetch";
  b.status = "Present";
  b.directoryTarget = true;
  b.partitionIdentifier = "p0";
  b.fileSystemType = "NTFS";

  fie::domain::ArtifactRecord a;
  a.category = "Browser";
  a.artifactName = "Chrome History";
  a.profile = "Alice";
  a.sourceLogicalPath = "/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History";
  a.status = "Present";
  a.sizeBytes = 1234;
  a.partitionIdentifier = "p0";
  a.fileSystemType = "NTFS";
  a.notes = "SQLite parsing deferred";
  a.details = fie::domain::ArtifactDetails{};
  a.details->provider = "windows.recycle_bin_i";
  a.details->state = fie::domain::ArtifactParseState::Parsed;
  a.details->summary = "parsed";
  a.details->originalPath = "C:\\\\Users\\\\Alice\\\\Desktop\\\\note.txt";
  a.details->originalSizeBytes = 42;

  QJsonArray rows = fie::cli::artifactsToJsonArray({b, a}, true);
  if (rows.size() != 2) return 1;

  const auto first = rows.at(0).toObject();
  const auto second = rows.at(1).toObject();

  if (first.value("category").toString() != "Browser") return 1;
  if (first.value("artifact_name").toString() != "Chrome History") return 1;
  if (first.value("source_logical_path").toString().isEmpty()) return 1;
  if (!first.contains("status") || !first.contains("notes") || !first.contains("partition_identifier")) return 1;
  if (!first.contains("details") || first.value("details").isNull()) return 1;
  const auto detailObj = first.value("details").toObject();
  if (detailObj.value("provider").toString() != "windows.recycle_bin_i") return 1;
  if (!detailObj.value("run_count").isNull()) return 1;
  if (!detailObj.value("target_path").isNull()) return 1;
  if (!detailObj.value("deletion_timestamp").isNull()) return 1;
  if (!detailObj.contains("amcache_entries") || !detailObj.value("amcache_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("bam_dam_entries") || !detailObj.value("bam_dam_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("appcompatcache_format") || !detailObj.value("appcompatcache_format").isNull()) return 1;
  if (!detailObj.contains("appcompatcache_entries") || !detailObj.value("appcompatcache_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("service_entries") || !detailObj.value("service_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("scheduled_task_entries") || !detailObj.value("scheduled_task_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("wer_report_entries") || !detailObj.value("wer_report_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("usb_device_entries") || !detailObj.value("usb_device_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("evtx_log_entries") || !detailObj.value("evtx_log_entries").toArray().isEmpty()) return 1;
  if (!detailObj.contains("jump_list_format") || !detailObj.value("jump_list_format").isNull()) return 1;
  if (!detailObj.contains("jump_list_entries") || !detailObj.value("jump_list_entries").toArray().isEmpty()) return 1;

  if (second.value("category").toString() != "Execution") return 1;
  if (!second.contains("directory_target") || !second.contains("size_bytes") || !second.contains("key_timestamp")) return 1;
  if (!second.contains("details") || !second.value("details").isNull()) return 1;

  fie::domain::ArtifactRecord evtx;
  evtx.category = "Event/System";
  evtx.artifactName = "EVTX files";
  evtx.profile = "SYSTEM";
  evtx.sourceLogicalPath = "/Windows/System32/winevt/Logs/Security.evtx";
  evtx.partitionIdentifier = "p0";
  evtx.fileSystemType = "NTFS";
  evtx.details = fie::domain::ArtifactDetails{};
  evtx.details->provider = "windows.evtx_v1";
  evtx.details->state = fie::domain::ArtifactParseState::Partial;
  fie::domain::ArtifactDetails::EvtxLogEntry evtxLog;
  evtxLog.logName = "Security.evtx";
  evtxLog.filePath = evtx.sourceLogicalPath;
  fie::domain::ArtifactDetails::EvtxEventEntry evtxEvent;
  evtxEvent.recordId = 42;
  evtxEvent.providerName = "Microsoft-Windows-Security-Auditing";
  evtxEvent.eventId = 4624;
  evtxEvent.computer = "HOST1";
  evtxEvent.eventData.push_back("TargetUserName=alice");
  evtxLog.events.push_back(std::move(evtxEvent));
  evtx.details->evtxLogEntries.push_back(std::move(evtxLog));

  QJsonArray evtxRows = fie::cli::artifactsToJsonArray({evtx}, true);
  if (evtxRows.size() != 1) return 1;
  const auto evtxObj = evtxRows.at(0).toObject();
  const auto evtxDetail = evtxObj.value("details").toObject();
  const auto evtxLogs = evtxDetail.value("evtx_log_entries").toArray();
  if (evtxLogs.size() != 1) return 1;
  const auto evtxLogObj = evtxLogs.at(0).toObject();
  const auto evtxEvents = evtxLogObj.value("events").toArray();
  if (evtxEvents.size() != 1) return 1;
  const auto evtxEventObj = evtxEvents.at(0).toObject();
  if (!evtxEventObj.contains("timestamp") || !evtxEventObj.value("timestamp").isNull()) return 1;
  if (!evtxEventObj.contains("level") || !evtxEventObj.value("level").isNull()) return 1;
  if (!evtxEventObj.contains("opcode") || !evtxEventObj.value("opcode").isNull()) return 1;
  if (!evtxEventObj.contains("task") || !evtxEventObj.value("task").isNull()) return 1;
  if (evtxEventObj.value("provider_name").toString().isEmpty()) return 1;

  return 0;
}

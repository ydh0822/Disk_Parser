#include "ForensicImageExtractor/forensics/ArtifactTimelineService.h"
#include "ForensicImageExtractor/cli/ArtifactTimelineJson.h"

int runArtifactTimelineServiceTests() {
  std::vector<fie::domain::ArtifactRecord> artifacts;

  fie::domain::ArtifactRecord recycle;
  recycle.category = "External";
  recycle.artifactName = "Recycle Bin";
  recycle.profile = "Alice";
  recycle.sourceLogicalPath = "/$Recycle.Bin/S-1/$I1";
  recycle.partitionIdentifier = "p1";
  recycle.fileSystemType = "NTFS";
  recycle.details = fie::domain::ArtifactDetails{};
  recycle.details->provider = "windows.recycle_bin_i";
  recycle.details->state = fie::domain::ArtifactParseState::Parsed;
  recycle.details->deletionTimestamp = QDateTime::fromString("2026-03-20T10:00:00Z", Qt::ISODate);
  recycle.details->originalPath = "C:/Users/Alice/Desktop/a.txt";
  recycle.details->originalSizeBytes = 123;
  artifacts.push_back(recycle);

  fie::domain::ArtifactRecord lnk;
  lnk.category = "External";
  lnk.artifactName = "LNK files";
  lnk.profile = "Alice";
  lnk.sourceLogicalPath = "/Users/Alice/Recent/a.lnk";
  lnk.partitionIdentifier = "p1";
  lnk.fileSystemType = "NTFS";
  lnk.details = fie::domain::ArtifactDetails{};
  lnk.details->provider = "windows.lnk_summary";
  lnk.details->state = fie::domain::ArtifactParseState::Partial;
  lnk.details->modifiedTimestamp = QDateTime::fromString("2026-03-18T10:00:00Z", Qt::ISODate);
  lnk.details->targetPath = "C:/Windows/System32/cmd.exe";
  lnk.details->warnings = {"truncated"};
  artifacts.push_back(lnk);

  fie::domain::ArtifactRecord pf;
  pf.category = "Execution";
  pf.artifactName = "Prefetch";
  pf.profile = "SYSTEM";
  pf.sourceLogicalPath = "/Windows/Prefetch/CMD.PF";
  pf.partitionIdentifier = "p1";
  pf.fileSystemType = "NTFS";
  pf.details = fie::domain::ArtifactDetails{};
  pf.details->provider = "windows.prefetch_summary";
  pf.details->state = fie::domain::ArtifactParseState::Failed;
  pf.details->executableName = "CMD.EXE";
  pf.details->runCount = 9;
  pf.details->error = "corrupt";
  artifacts.push_back(pf);

  fie::domain::ArtifactRecord browser;
  browser.category = "Browser";
  browser.artifactName = "Chrome History";
  browser.profile = "Alice";
  browser.sourceLogicalPath = "/Users/Alice/.../History";
  browser.partitionIdentifier = "p1";
  browser.fileSystemType = "NTFS";
  browser.details = fie::domain::ArtifactDetails{};
  browser.details->provider = "windows.chromium_history";
  browser.details->state = fie::domain::ArtifactParseState::Parsed;
  browser.details->browserVisits.push_back(
      {.timestamp = QDateTime::fromString("2026-03-19T10:00:00Z", Qt::ISODate), .url = "https://example.com", .title = "Example", .visitCount = 3});
  browser.details->browserDownloads.push_back(
      {.timestamp = QDateTime::fromString("2026-03-19T11:00:00Z", Qt::ISODate), .url = "https://example.com/a.zip", .targetPath = "C:/Users/Alice/Downloads/a.zip"});
  artifacts.push_back(browser);

  fie::domain::ArtifactRecord unsupported;
  unsupported.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";
  artifacts.push_back(unsupported);

  fie::forensics::ArtifactTimelineService svc;
  const auto events = svc.buildEvents(artifacts);
  if (events.size() < 6) return 1;

  // deterministic sort: timed first (lnk modified before recycle deletion)
  if (!events[0].timestamp.has_value()) return 1;
  if (events[0].eventType != "lnk_modified") return 1;
  if (events[1].eventType != "recycle_bin_deletion") return 1;

  bool sawFailedStatus = false;
  bool sawUnsupported = false;
  bool sawBrowserVisit = false;
  bool sawBrowserDownload = false;
  for (const auto &e : events) {
    if (e.eventType == "artifact_parse_status" && e.parseState == fie::domain::ArtifactParseState::Failed) sawFailedStatus = true;
    if (e.sourceLogicalPath == unsupported.sourceLogicalPath) sawUnsupported = true;
    if (e.eventType == "browser_visit") sawBrowserVisit = true;
    if (e.eventType == "browser_download") sawBrowserDownload = true;
  }
  if (!sawFailedStatus) return 1;
  if (sawUnsupported) return 1;
  if (!sawBrowserVisit || !sawBrowserDownload) return 1;

  const auto json = fie::cli::artifactEventsToJsonArray(events);
  if (json.isEmpty()) return 1;
  const auto first = json.at(0).toObject();
  if (!first.contains("fields")) return 1;

  // null handling
  bool sawNull = false;
  for (const auto &v : json) {
    const auto o = v.toObject();
    if (o.value("timestamp").isNull()) {
      sawNull = true;
      break;
    }
  }
  if (!sawNull) return 1;

  return 0;
}

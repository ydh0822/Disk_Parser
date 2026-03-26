#pragma once

#include "ForensicImageExtractor/domain/Models.h"

namespace fie::gui {

enum class ArtifactDetailPanelState {
  Loading,
  Unsupported,
  Parsed,
  Partial,
  Failed,
};

inline QString artifactParseStateLabel(domain::ArtifactParseState state) {
  switch (state) {
  case domain::ArtifactParseState::Unsupported: return "Unsupported";
  case domain::ArtifactParseState::Parsed: return "Parsed";
  case domain::ArtifactParseState::Partial: return "Partial";
  case domain::ArtifactParseState::Failed: return "Failed";
  }
  return "Unsupported";
}

inline QString panelStateLabel(ArtifactDetailPanelState state) {
  switch (state) {
  case ArtifactDetailPanelState::Loading: return "loading";
  case ArtifactDetailPanelState::Unsupported: return "unsupported";
  case ArtifactDetailPanelState::Parsed: return "parsed";
  case ArtifactDetailPanelState::Partial: return "partial";
  case ArtifactDetailPanelState::Failed: return "failed";
  }
  return "unsupported";
}

inline QString formatArtifactDetailsText(const std::optional<domain::ArtifactDetails> &details,
                                         ArtifactDetailPanelState state) {
  if (state == ArtifactDetailPanelState::Loading) {
    return "[Details]\nParser-backed details are loading for the selected artifact...";
  }
  if (state == ArtifactDetailPanelState::Unsupported || !details.has_value()) {
    return "[Details]\nParser-backed details are unsupported for this artifact type.";
  }
  const auto &d = *details;
  const auto dt = [](const std::optional<QDateTime> &v) { return v ? v->toString(Qt::ISODate) : QString("-"); };
  QStringList runs;
  for (const auto &t : d.lastRunTimestamps) runs.push_back(t.toString(Qt::ISODate));
  const QString runTimes = runs.isEmpty() ? "-" : runs.join(", ");
  const QString warnings = d.warnings.isEmpty() ? "-" : d.warnings.join(" | ");
  auto firstN = [](const QStringList &items, int n = 3) {
    if (items.isEmpty()) return QString("-");
    QStringList out;
    for (int i = 0; i < items.size() && i < n; ++i) out.push_back(items[i]);
    if (items.size() > n) out.push_back("...");
    return out.join(" | ");
  };

  QStringList runMruPreview;
  for (const auto &e : d.registryRunMruEntries) {
    runMruPreview.push_back(QString("%1=%2").arg(e.valueName, e.command));
  }
  QStringList typedPreview;
  for (const auto &e : d.registryTypedPathEntries) {
    typedPreview.push_back(QString("%1=%2").arg(e.valueName, e.path));
  }
  QStringList recentPreview;
  for (const auto &e : d.registryRecentDocEntries) {
    recentPreview.push_back(QString("%1:%2").arg(e.extensionGroup, e.documentName));
  }
  QStringList uaPreview;
  for (const auto &e : d.registryUserAssistEntries) {
    uaPreview.push_back(e.decodedName.isEmpty() ? e.encodedName : e.decodedName);
  }
  QStringList amcachePreview;
  for (const auto &e : d.amcacheEntries) {
    amcachePreview.push_back(e.programPath.isEmpty() ? e.fileName : e.programPath);
  }
  QStringList bamDamPreview;
  for (const auto &e : d.bamDamEntries) {
    bamDamPreview.push_back(QString("%1:%2").arg(e.source, e.executablePath));
  }
  QStringList jumpListPreview;
  for (const auto &e : d.jumpListEntries) {
    jumpListPreview.push_back(!e.targetPath.isEmpty() ? e.targetPath
                                                       : (e.targetSummary.isEmpty() ? e.entryIdentifier : e.targetSummary));
  }
  QStringList appCompatPreview;
  for (const auto &e : d.appCompatCacheEntries) {
    appCompatPreview.push_back(e.executablePath);
  }
  QStringList servicePreview;
  for (const auto &e : d.serviceEntries) {
    servicePreview.push_back(e.serviceName.isEmpty() ? e.displayName : e.serviceName);
  }
  QStringList taskPreview;
  for (const auto &e : d.scheduledTaskEntries) {
    taskPreview.push_back(e.taskName.isEmpty() ? e.taskPath : e.taskName);
  }
  QStringList werPreview;
  for (const auto &e : d.werReportEntries) {
    werPreview.push_back(e.reportName.isEmpty() ? e.eventType : e.reportName);
  }
  QStringList usbPreview;
  for (const auto &e : d.usbDeviceEntries) {
    usbPreview.push_back(e.friendlyName.isEmpty() ? e.deviceIdentifier : e.friendlyName);
  }
  QStringList evtxPreview;
  for (const auto &e : d.evtxLogEntries) {
    evtxPreview.push_back(e.logName.isEmpty() ? e.filePath : e.logName);
  }

  return QString("[Details]\n"
                 "Provider     : %1\n"
                 "State        : %2\n"
                 "Summary      : %3\n"
                 "Error        : %4\n"
                 "Warnings     : %5\n"
                 "\n[Parsed Fields]\n"
                 "Original path: %6\n"
                 "Deleted at   : %7\n"
                 "Original size: %8\n"
                 "Target path  : %9\n"
                 "Working dir  : %10\n"
                 "Arguments    : %11\n"
                 "Relative path: %12\n"
                 "Created time : %13\n"
                 "Modified time: %14\n"
                 "Accessed time: %15\n"
                 "Executable   : %16\n"
                 "Format ver   : %17\n"
                 "Run count    : %18\n"
                 "Last runs    : %19\n"
                 "Browser visits: %20\n"
                 "Browser downloads: %21\n"
                 "Registry RunMRU count: %22\n"
                 "Registry RunMRU preview: %23\n"
                 "Registry TypedPaths count: %24\n"
                 "Registry TypedPaths preview: %25\n"
                 "Registry RecentDocs count: %26\n"
                 "Registry RecentDocs preview: %27\n"
                 "Registry UserAssist count: %28\n"
                 "Registry UserAssist preview: %29\n"
                 "Amcache count : %30\n"
                 "Amcache preview: %31\n"
                 "BAM/DAM count : %32\n"
                 "BAM/DAM preview: %33\n"
                 "Jump List format: %34\n"
                 "Jump List version: %35\n"
                 "Jump List reported count: %36\n"
                 "Jump List entries: %37\n"
                 "Jump List preview: %38\n"
                 "AppCompatCache format: %39\n"
                 "AppCompatCache count: %40\n"
                 "AppCompatCache preview: %41\n"
                 "Services count: %42\n"
                 "Services preview: %43\n"
                 "Scheduled Tasks count: %44\n"
                 "Scheduled Tasks preview: %45\n"
                 "WER reports count: %46\n"
                 "WER reports preview: %47\n"
                 "USB devices count: %48\n"
                 "USB devices preview: %49\n"
                 "EVTX logs count: %50\n"
                 "EVTX logs preview: %51")
      .arg(d.provider,
           artifactParseStateLabel(d.state),
           d.summary.isEmpty() ? "-" : d.summary,
           d.error.isEmpty() ? "-" : d.error,
           warnings,
           d.originalPath.isEmpty() ? "-" : d.originalPath,
           dt(d.deletionTimestamp),
           d.originalSizeBytes ? QString::number(*d.originalSizeBytes) : "-",
           d.targetPath.isEmpty() ? "-" : d.targetPath,
           d.workingDirectory.isEmpty() ? "-" : d.workingDirectory,
           d.commandLineArguments.isEmpty() ? "-" : d.commandLineArguments,
           d.relativePath.isEmpty() ? "-" : d.relativePath,
           dt(d.createdTimestamp),
           dt(d.modifiedTimestamp),
           dt(d.accessedTimestamp),
           d.executableName.isEmpty() ? "-" : d.executableName,
           d.formatVersion ? QString::number(*d.formatVersion) : "-",
           d.runCount ? QString::number(*d.runCount) : "-",
           runTimes,
           QString::number(static_cast<int>(d.browserVisits.size())),
           QString::number(static_cast<int>(d.browserDownloads.size())),
           QString::number(static_cast<int>(d.registryRunMruEntries.size())),
           firstN(runMruPreview),
           QString::number(static_cast<int>(d.registryTypedPathEntries.size())),
           firstN(typedPreview),
           QString::number(static_cast<int>(d.registryRecentDocEntries.size())),
           firstN(recentPreview),
           QString::number(static_cast<int>(d.registryUserAssistEntries.size())),
           firstN(uaPreview),
           QString::number(static_cast<int>(d.amcacheEntries.size())),
           firstN(amcachePreview),
           QString::number(static_cast<int>(d.bamDamEntries.size())),
           firstN(bamDamPreview),
           d.jumpListFormat.isEmpty() ? "-" : d.jumpListFormat,
           d.jumpListVersion ? QString::number(*d.jumpListVersion) : "-",
           d.jumpListReportedEntryCount ? QString::number(*d.jumpListReportedEntryCount) : "-",
           QString::number(static_cast<int>(d.jumpListEntries.size())),
           firstN(jumpListPreview),
           d.appCompatCacheFormat.isEmpty() ? "-" : d.appCompatCacheFormat,
           QString::number(static_cast<int>(d.appCompatCacheEntries.size())),
           firstN(appCompatPreview),
           QString::number(static_cast<int>(d.serviceEntries.size())),
           firstN(servicePreview),
           QString::number(static_cast<int>(d.scheduledTaskEntries.size())),
           firstN(taskPreview),
           QString::number(static_cast<int>(d.werReportEntries.size())),
           firstN(werPreview),
           QString::number(static_cast<int>(d.usbDeviceEntries.size())),
           firstN(usbPreview),
           QString::number(static_cast<int>(d.evtxLogEntries.size())),
           firstN(evtxPreview));
}

} // namespace fie::gui

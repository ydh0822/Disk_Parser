#include "ForensicImageExtractor/gui/ArtifactDetailsText.h"

int runArtifactDetailsTextTests() {
  const QString loading = fie::gui::formatArtifactDetailsText(std::nullopt, fie::gui::ArtifactDetailPanelState::Loading);
  if (!loading.contains("loading")) return 1;

  const QString unsupported =
      fie::gui::formatArtifactDetailsText(std::nullopt, fie::gui::ArtifactDetailPanelState::Unsupported);
  if (!unsupported.contains("unsupported")) return 1;

  fie::domain::ArtifactDetails details;
  details.provider = "windows.prefetch_summary";
  details.state = fie::domain::ArtifactParseState::Partial;
  details.summary = "Prefetch summary parsed";
  details.warnings = {"Truncated data"};
  details.executableName = "CMD.EXE";
  details.runCount = 2;
  details.registryRunMruEntries.push_back({.valueName = "a", .command = "cmd.exe", .mruPosition = 0});
  details.registryTypedPathEntries.push_back({.valueName = "url1", .path = "C:\\Windows"});
  details.registryRecentDocEntries.push_back({.valueName = "0", .documentName = "alpha.txt", .extensionGroup = ".txt", .mruPosition = 0});
  details.registryUserAssistEntries.push_back({.encodedName = "pzq.rkr", .decodedName = "cmd.exe", .runCount = 1, .lastExecution = std::nullopt});
  details.amcacheEntries.push_back({.programPath = "c:\\program files\\app\\app.exe", .fileName = "app.exe"});
  details.bamDamEntries.push_back({.source = "bam", .sid = "S-1", .executablePath = "C:\\Windows\\System32\\cmd.exe"});

  const QString rendered = fie::gui::formatArtifactDetailsText(details, fie::gui::ArtifactDetailPanelState::Partial);
  if (!rendered.contains("windows.prefetch_summary")) return 1;
  if (!rendered.contains("Partial")) return 1;
  if (!rendered.contains("CMD.EXE")) return 1;
  if (!rendered.contains("Truncated data")) return 1;
  if (!rendered.contains("Registry RunMRU count: 1")) return 1;
  if (!rendered.contains("Registry TypedPaths count: 1")) return 1;
  if (!rendered.contains("Registry RecentDocs count: 1")) return 1;
  if (!rendered.contains("Registry UserAssist count: 1")) return 1;
  if (!rendered.contains("Amcache count : 1")) return 1;
  if (!rendered.contains("BAM/DAM count : 1")) return 1;
  if (!rendered.contains("a=cmd.exe")) return 1;
  if (!rendered.contains("bam:C:\\Windows\\System32\\cmd.exe")) return 1;

  return 0;
}

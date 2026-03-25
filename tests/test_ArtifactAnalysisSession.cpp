#include "ForensicImageExtractor/gui/ArtifactAnalysisSession.h"

int runArtifactAnalysisSessionTests() {
  std::vector<fie::domain::ArtifactRecord> artifacts;

  fie::domain::ArtifactRecord present;
  present.status = "Present";
  present.sourceLogicalPath = "/a";
  present.details = fie::domain::ArtifactDetails{};
  present.details->state = fie::domain::ArtifactParseState::Parsed;
  artifacts.push_back(present);

  fie::domain::ArtifactRecord partial;
  partial.status = "Present";
  partial.sourceLogicalPath = "/b";
  partial.details = fie::domain::ArtifactDetails{};
  partial.details->state = fie::domain::ArtifactParseState::Partial;
  artifacts.push_back(partial);

  fie::domain::ArtifactRecord failed;
  failed.status = "Present";
  failed.sourceLogicalPath = "/c";
  failed.details = fie::domain::ArtifactDetails{};
  failed.details->state = fie::domain::ArtifactParseState::Failed;
  artifacts.push_back(failed);

  fie::domain::ArtifactRecord unsupported;
  unsupported.status = "Present";
  unsupported.sourceLogicalPath = "/d";
  artifacts.push_back(unsupported);

  fie::domain::ArtifactRecord missing;
  missing.status = "Missing";
  missing.sourceLogicalPath = "/e";
  artifacts.push_back(missing);

  std::vector<fie::domain::ArtifactEventRecord> events;
  fie::domain::ArtifactEventRecord e1;
  e1.eventType = "prefetch_last_run";
  events.push_back(e1);
  fie::domain::ArtifactEventRecord e2;
  e2.eventType = "prefetch_last_run";
  events.push_back(e2);
  fie::domain::ArtifactEventRecord e3;
  e3.eventType = "recycle_bin_deletion";
  events.push_back(e3);

  const auto summary = fie::gui::buildAnalysisSummary(artifacts, events);
  if (summary.totalArtifacts != 5) return 1;
  if (summary.supportedAnalyzed != 4) return 1;
  if (summary.parsed != 1 || summary.partial != 1 || summary.failed != 1 || summary.unsupported != 1) return 1;
  if (summary.totalEvents != 3) return 1;
  if (summary.eventCountsByType.value("prefetch_last_run") != 2) return 1;

  if (!fie::gui::shouldApplyAnalysisResult(2, "ctx", "ctx", 2, "ctx")) return 1;
  if (fie::gui::shouldApplyAnalysisResult(2, "ctx", "ctx", 1, "ctx")) return 1;
  if (fie::gui::shouldApplyAnalysisResult(2, "ctx", "other", 2, "ctx")) return 1;

  const QString text = fie::gui::formatAnalysisSummary(summary);
  if (!text.contains("parsed=1") || !text.contains("events=3")) return 1;

  return 0;
}

#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QMap>
#include <QString>

namespace fie::gui {

struct ArtifactAnalysisSummary {
  int totalArtifacts{0};
  int supportedAnalyzed{0};
  int parsed{0};
  int partial{0};
  int failed{0};
  int unsupported{0};
  int totalEvents{0};
  QMap<QString, int> eventCountsByType;
};

inline bool shouldAnalyzeArtifact(const domain::ArtifactRecord &artifact) {
  return artifact.status.compare("Present", Qt::CaseInsensitive) == 0 && !artifact.directoryTarget;
}

inline bool shouldApplyAnalysisResult(quint64 activeRunId,
                                      const QString &activeContext,
                                      const QString &currentContext,
                                      quint64 resultRunId,
                                      const QString &resultContext) {
  return activeRunId != 0 && resultRunId == activeRunId &&
         resultContext.compare(activeContext, Qt::CaseInsensitive) == 0 &&
         resultContext.compare(currentContext, Qt::CaseInsensitive) == 0;
}

inline ArtifactAnalysisSummary buildAnalysisSummary(const std::vector<domain::ArtifactRecord> &artifacts,
                                                    const std::vector<domain::ArtifactEventRecord> &events) {
  ArtifactAnalysisSummary summary;
  summary.totalArtifacts = static_cast<int>(artifacts.size());
  summary.totalEvents = static_cast<int>(events.size());

  for (const auto &event : events) {
    summary.eventCountsByType[event.eventType] += 1;
  }

  for (const auto &artifact : artifacts) {
    if (!shouldAnalyzeArtifact(artifact)) continue;
    ++summary.supportedAnalyzed;
    if (!artifact.details.has_value()) {
      ++summary.unsupported;
      continue;
    }
    switch (artifact.details->state) {
    case domain::ArtifactParseState::Parsed: ++summary.parsed; break;
    case domain::ArtifactParseState::Partial: ++summary.partial; break;
    case domain::ArtifactParseState::Failed: ++summary.failed; break;
    case domain::ArtifactParseState::Unsupported: ++summary.unsupported; break;
    }
  }

  return summary;
}

inline QString formatAnalysisSummary(const ArtifactAnalysisSummary &summary) {
  QStringList eventParts;
  for (auto it = summary.eventCountsByType.cbegin(); it != summary.eventCountsByType.cend(); ++it) {
    eventParts.push_back(QString("%1=%2").arg(it.key(), QString::number(it.value())));
  }
  const QString events = eventParts.isEmpty() ? "none" : eventParts.join(", ");
  return QString("Analysis summary | artifacts=%1 analyzed=%2 parsed=%3 partial=%4 failed=%5 unsupported=%6 | events=%7 [%8]")
      .arg(summary.totalArtifacts)
      .arg(summary.supportedAnalyzed)
      .arg(summary.parsed)
      .arg(summary.partial)
      .arg(summary.failed)
      .arg(summary.unsupported)
      .arg(summary.totalEvents)
      .arg(events);
}

} // namespace fie::gui

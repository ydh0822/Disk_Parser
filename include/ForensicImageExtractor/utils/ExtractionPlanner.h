#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QString>
#include <vector>

namespace fie::utils {

QString sanitizeLogicalPath(const QString &logicalPath);
QString composeDestinationPath(const QString &root, const QString &logicalPath);
QString resolveDestinationPath(const QString &requestedPath, domain::OverwriteMode mode, QString &decisionStatus);
std::vector<quint64> buildChunkPlan(quint64 totalSize, quint64 chunkSize);
QStringList deduplicateOrderedPaths(const QStringList &paths);
QString successOutcomeFromDecision(const QString &decision);
QString finalStatusFromOutcome(const QString &primaryOutcome, bool hasWarning, bool hasError);

} // namespace fie::utils

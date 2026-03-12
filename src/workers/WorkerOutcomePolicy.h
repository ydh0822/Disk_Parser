#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QStringList>
#include <utility>
#include <vector>

namespace fie::workers::detail {

std::pair<std::vector<domain::FileEntry>, domain::ForensicOperationResult>
resolveDirectoryListOutcome(std::vector<domain::FileEntry> entries,
                            const QString &error,
                            bool cancellationObserved,
                            domain::ForensicBackend backend);

std::pair<std::vector<domain::ArtifactRecord>, domain::ForensicOperationResult>
resolveArtifactDiscoveryOutcome(std::vector<domain::ArtifactRecord> artifacts,
                                const QStringList &warnings,
                                bool cancellationObserved,
                                domain::ForensicBackend backend);

std::pair<std::vector<domain::ExtractionResult>, domain::ForensicOperationResult>
resolveExtractionOutcome(std::vector<domain::ExtractionResult> results,
                         const QString &error,
                         bool cancellationObserved,
                         domain::ForensicBackend backend);

} // namespace fie::workers::detail

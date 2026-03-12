#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <functional>
#include <vector>

namespace fie::forensics {

class ArtifactDiscoveryService {
public:
  using ListDirectoryFn = std::function<std::vector<domain::FileEntry>(const QString &, QString &)>;
  using IsCancelledFn = std::function<bool()>;

  std::vector<domain::ArtifactRecord> discover(const domain::PartitionInfo &partition,
                                               const ListDirectoryFn &listDirectory,
                                               QStringList &warnings,
                                               const IsCancelledFn &isCancelled = {}) const;
};

} // namespace fie::forensics

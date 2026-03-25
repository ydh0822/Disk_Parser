#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <vector>

namespace fie::forensics {

class ArtifactTimelineService {
public:
  std::vector<domain::ArtifactEventRecord> buildEvents(const std::vector<domain::ArtifactRecord> &artifacts) const;
};

} // namespace fie::forensics

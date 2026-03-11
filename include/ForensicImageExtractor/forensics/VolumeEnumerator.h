#pragma once

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"

#include <vector>

namespace fie::forensics {

class VolumeEnumerator {
public:
  std::vector<domain::PartitionInfo> enumerate(const core::TskImageHandleAdapter &image,
                                               QString &error) const;
};

} // namespace fie::forensics

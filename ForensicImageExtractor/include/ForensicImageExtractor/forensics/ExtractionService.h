#pragma once

#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/forensics/FileSystemHandle.h"

#include <vector>

namespace fie::forensics {

class ExtractionService {
public:
  std::vector<domain::ExtractionResult> extract(const FileSystemHandle &fs,
                                                const domain::ExtractionTask &task,
                                                QString &error) const;
};

} // namespace fie::forensics

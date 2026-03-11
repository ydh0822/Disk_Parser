#pragma once

#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/forensics/FileSystemHandle.h"
#include "ForensicImageExtractor/forensics/TaskContext.h"

#include <vector>

namespace fie::forensics {

class ExtractionService {
public:
  std::vector<domain::ExtractionResult> extract(const FileSystemHandle &fs,
                                                const domain::ExtractionTask &task,
                                                QString &error,
                                                const TaskContext *context = nullptr) const;

  // Test helper used to validate cancellation/progress semantics without TSK coupling.
  static bool simulateChunkLoopForTesting(quint64 totalBytes, quint64 chunkSize, QString &error,
                                          const TaskContext *context = nullptr);
};

} // namespace fie::forensics

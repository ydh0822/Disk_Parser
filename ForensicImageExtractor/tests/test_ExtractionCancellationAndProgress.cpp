#include "ForensicImageExtractor/forensics/ExtractionService.h"

int runExtractionCancellationAndProgressTests() {
  fie::forensics::ExtractionService service;

  std::shared_ptr<fie::forensics::CancellationToken> token = std::make_shared<fie::forensics::CancellationToken>();
  fie::forensics::TaskContext context;
  context.cancellation = token;

  quint64 lastProcessed = 0;
  bool monotonic = true;
  int updates = 0;
  context.onProgress = [&](const fie::forensics::ProgressInfo &info) {
    ++updates;
    if (info.totalBytesProcessed < lastProcessed) {
      monotonic = false;
    }
    lastProcessed = info.totalBytesProcessed;
    if (updates == 2) {
      token->cancel();
    }
  };

  QString error;
  const bool completed = service.simulateChunkLoopForTesting(1024, 256, error, &context);
  if (completed) {
    return 1;
  }
  if (error != "Task cancelled") {
    return 1;
  }
  if (!monotonic || updates < 2) {
    return 1;
  }

  // Non-cancelled run should finish.
  fie::forensics::TaskContext okContext;
  QString okError;
  if (!service.simulateChunkLoopForTesting(1024, 256, okError, &okContext)) {
    return 1;
  }

  return 0;
}

#include "ForensicImageExtractor/workers/ExtractionWorker.h"

#include "ForensicImageExtractor/forensics/ExtractionService.h"

namespace fie::workers {

ExtractionWorker::ExtractionWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                                   fie::domain::ExtractionTask task)
    : m_tskImage(std::move(tskImage)), m_task(std::move(task)),
      m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void ExtractionWorker::requestCancel() { m_cancel->cancel(); }

void ExtractionWorker::process() {
  if (!m_tskImage || !m_tskImage->isOpen()) {
    emit completed({}, "TSK image not open");
    return;
  }

  forensics::FileSystemHandle fs;
  QString error;
  if (!fs.open(*m_tskImage, m_task.partition, error)) {
    emit completed({}, error);
    return;
  }

  forensics::TaskContext context;
  context.cancellation = m_cancel;
  context.onProgress = [this](const forensics::ProgressInfo &info) { emit progress(info); };

  forensics::ExtractionService service;
  const auto results = service.extract(fs, m_task, error, &context);
  emit completed(results, error);
}

} // namespace fie::workers

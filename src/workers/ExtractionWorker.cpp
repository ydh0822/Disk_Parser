#include "ForensicImageExtractor/workers/ExtractionWorker.h"

#include "ForensicImageExtractor/forensics/ExtractionService.h"

#include "WorkerOutcomePolicy.h"

namespace fie::workers {

ExtractionWorker::ExtractionWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                                   fie::domain::ExtractionTask task)
    : m_tskImage(std::move(tskImage)), m_task(std::move(task)),
      m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void ExtractionWorker::requestCancel() { m_cancel->cancel(); }

void ExtractionWorker::process() {
  if (m_cancel->isCancellationRequested()) {
    emit completed({}, domain::op::cancelled());
    return;
  }

  if (!m_tskImage || !m_tskImage->isOpen()) {
    emit completed({}, domain::op::failure("image_not_open", "TSK image not open"));
    return;
  }

  const auto backend = domain::op::backendFromOpenAdapter(*m_tskImage);

  forensics::FileSystemHandle fs;
  QString error;
  if (!fs.open(*m_tskImage, m_task.partition, error)) {
    emit completed({}, domain::op::failure("filesystem_open_failed", error, backend));
    return;
  }

  forensics::TaskContext context;
  context.cancellation = m_cancel;
  context.onProgress = [this](const forensics::ProgressInfo &info) { emit progress(info); };

  forensics::ExtractionService service;
  auto results = service.extract(fs, m_task, error, &context);
  const auto resolved =
      detail::resolveExtractionOutcome(std::move(results), error, m_cancel->isCancellationRequested(), backend);
  emit completed(resolved.first, resolved.second);
}

} // namespace fie::workers

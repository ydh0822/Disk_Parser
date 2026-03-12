#pragma once

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/forensics/TaskContext.h"

#include <QObject>
#include <memory>
#include <vector>

namespace fie::workers {

class ExtractionWorker : public QObject {
  Q_OBJECT
public:
  ExtractionWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage, fie::domain::ExtractionTask task);

public slots:
  void process();
  void requestCancel();


signals:
  void progress(fie::forensics::ProgressInfo progress);
  void completed(std::vector<fie::domain::ExtractionResult> results, fie::domain::ForensicOperationResult result);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  fie::domain::ExtractionTask m_task;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};

} // namespace fie::workers

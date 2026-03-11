#pragma once

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"

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

signals:
  void completed(std::vector<fie::domain::ExtractionResult> results, QString error);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  fie::domain::ExtractionTask m_task;
};

} // namespace fie::workers

#pragma once

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/forensics/TaskContext.h"

#include <QObject>
#include <memory>
#include <vector>

namespace fie::workers {

class ImageOpenWorker : public QObject {
  Q_OBJECT
public:
  ImageOpenWorker(std::shared_ptr<core::IImageReader> reader, QString path);

public slots:
  void process();
  void requestCancel();

signals:
  void completed(bool ok, fie::domain::ImageInfo info, QString error);

private:
  std::shared_ptr<core::IImageReader> m_reader;
  QString m_path;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};

class PartitionScanWorker : public QObject {
  Q_OBJECT
public:
  explicit PartitionScanWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage);

public slots:
  void process();
  void requestCancel();

signals:
  void completed(std::vector<fie::domain::PartitionInfo> partitions, QString error, QString warning);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};

class DirectoryListWorker : public QObject {
  Q_OBJECT
public:
  DirectoryListWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                      fie::domain::PartitionInfo partition, QString path);

public slots:
  void process();
  void requestCancel();

signals:
  void completed(std::vector<fie::domain::FileEntry> entries, QString error);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  fie::domain::PartitionInfo m_partition;
  QString m_path;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};


class ArtifactScanWorker : public QObject {
  Q_OBJECT
public:
  ArtifactScanWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                     fie::domain::PartitionInfo partition);

public slots:
  void process();
  void requestCancel();

signals:
  void completed(std::vector<fie::domain::ArtifactRecord> artifacts, QStringList warnings, QString error);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  fie::domain::PartitionInfo m_partition;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};

} // namespace fie::workers

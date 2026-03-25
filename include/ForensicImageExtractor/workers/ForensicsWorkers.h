#pragma once

#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/forensics/TaskContext.h"

#include <QObject>
#include <memory>
#include <optional>
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
  void completed(fie::domain::ImageInfo info, fie::domain::ForensicOperationResult result);

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
  void completed(std::vector<fie::domain::PartitionInfo> partitions, fie::domain::ForensicOperationResult result);

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
  void completed(std::vector<fie::domain::FileEntry> entries, fie::domain::ForensicOperationResult result);

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
  void completed(std::vector<fie::domain::ArtifactRecord> artifacts, fie::domain::ForensicOperationResult result);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  fie::domain::PartitionInfo m_partition;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};

class ArtifactDetailWorker : public QObject {
  Q_OBJECT
public:
  ArtifactDetailWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                       fie::domain::PartitionInfo partition,
                       fie::domain::ArtifactRecord artifact);

public slots:
  void process();
  void requestCancel();

signals:
  void completed(QString cacheKey,
                 fie::domain::ArtifactRecord artifact,
                 fie::domain::ForensicOperationResult result);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  fie::domain::PartitionInfo m_partition;
  fie::domain::ArtifactRecord m_artifact;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};

class ArtifactAnalysisWorker : public QObject {
  Q_OBJECT
public:
  ArtifactAnalysisWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                         fie::domain::PartitionInfo partition,
                         std::vector<fie::domain::ArtifactRecord> artifacts);

public slots:
  void process();
  void requestCancel();

signals:
  void progress(int processed, int total, QString sourcePath);
  void completed(QString contextKey,
                 std::vector<fie::domain::ArtifactRecord> analyzedArtifacts,
                 fie::domain::ForensicOperationResult result);

private:
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  fie::domain::PartitionInfo m_partition;
  std::vector<fie::domain::ArtifactRecord> m_artifacts;
  std::shared_ptr<forensics::CancellationToken> m_cancel;
};

} // namespace fie::workers

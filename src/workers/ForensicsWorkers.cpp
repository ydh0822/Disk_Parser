#include "ForensicImageExtractor/workers/ForensicsWorkers.h"

#include "ForensicImageExtractor/core/EwfSegmentResolver.h"
#include "ForensicImageExtractor/domain/ForensicOperationResultUtils.h"
#include "ForensicImageExtractor/forensics/ArtifactDiscoveryService.h"
#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"
#include "ForensicImageExtractor/forensics/ArtifactDataAccess.h"
#include "ForensicImageExtractor/forensics/FileSystemBrowser.h"
#include "ForensicImageExtractor/forensics/FileSystemHandle.h"
#include "ForensicImageExtractor/forensics/VolumeEnumerator.h"

#include "WorkerOutcomePolicy.h"

namespace fie::workers {

namespace {
bool isKnownUnsupportedOrUnconfirmedFs(const QString &fsType) {
  const QString upper = fsType.toUpper();
  return upper.contains("REFS") || upper.contains("XFS");
}
}

ImageOpenWorker::ImageOpenWorker(std::shared_ptr<core::IImageReader> reader, QString path)
    : m_reader(std::move(reader)), m_path(std::move(path)),
      m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void ImageOpenWorker::requestCancel() { m_cancel->cancel(); }

void ImageOpenWorker::process() {
  fie::domain::ImageInfo info;
  if (m_cancel->isCancellationRequested()) {
    emit completed(info, domain::op::cancelled());
    return;
  }

  QString error;
  const bool ok = m_reader && m_reader->open(m_path, error);
  if (m_cancel->isCancellationRequested()) {
    emit completed(info, domain::op::cancelled());
    return;
  }
  if (!ok) {
    emit completed(info, domain::op::failure("image_reader_open_failed", error));
    return;
  }

  info.path = m_path;
  info.sizeBytes = m_reader->size();
  info.format = fie::core::isEwfPath(m_path) ? "EWF" : "RAW/DD";
  if (!m_reader->lastWarning().isEmpty()) {
    emit completed(info, domain::op::successWithWarning(domain::ForensicBackend::NotApplicable,
                                                        "image_reader_open_warning",
                                                        "Image opened with warning",
                                                        m_reader->lastWarning()));
    return;
  }
  emit completed(info,
                 domain::op::success(domain::ForensicBackend::NotApplicable, "image_reader_opened", "Image opened"));
}

PartitionScanWorker::PartitionScanWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage)
    : m_tskImage(std::move(tskImage)), m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void PartitionScanWorker::requestCancel() { m_cancel->cancel(); }

void PartitionScanWorker::process() {
  if (!m_tskImage) {
    emit completed({}, domain::op::failure("missing_adapter", "TSK image adapter missing"));
    return;
  }
  if (m_cancel->isCancellationRequested()) {
    emit completed({}, domain::op::cancelled());
    return;
  }

  QString openError;
  if (!m_tskImage->open(openError)) {
    emit completed({}, domain::op::failure("tsk_image_open_failed", openError,
                                           domain::op::backendForImageOpenFailure(*m_tskImage)));
    return;
  }
  if (m_cancel->isCancellationRequested()) {
    emit completed({}, domain::op::cancelled(domain::op::backendFromOpenAdapter(*m_tskImage)));
    return;
  }

  forensics::VolumeEnumerator enumerator;
  QString error;
  const auto parts = enumerator.enumerate(*m_tskImage, error);
  const auto backend = domain::op::backendFromOpenAdapter(*m_tskImage);
  const auto warning = m_tskImage->lastWarning();

  if (m_cancel->isCancellationRequested()) {
    emit completed({}, domain::op::cancelled(backend));
    return;
  }

  if (!error.isEmpty()) {
    emit completed({}, domain::op::failure("partition_enumeration_failed", error, backend));
    return;
  }

  if (!warning.isEmpty()) {
    emit completed(parts, domain::op::successWithWarning(backend,
                                                         "partition_enumeration_with_fallback",
                                                         "Partitions enumerated using fallback backend",
                                                         warning));
    return;
  }

  emit completed(parts, domain::op::success(backend, "partition_enumerated", "Partitions enumerated"));
}

DirectoryListWorker::DirectoryListWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                                         fie::domain::PartitionInfo partition,
                                         QString path)
    : m_tskImage(std::move(tskImage)), m_partition(std::move(partition)), m_path(std::move(path)),
      m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void DirectoryListWorker::requestCancel() { m_cancel->cancel(); }

void DirectoryListWorker::process() {
  if (m_cancel->isCancellationRequested()) {
    emit completed({}, domain::op::cancelled());
    return;
  }

  if (!m_tskImage || !m_tskImage->isOpen()) {
    emit completed({}, domain::op::failure("image_not_open", "TSK image not open"));
    return;
  }
  const auto backend = domain::op::backendFromOpenAdapter(*m_tskImage);

  QString error;
  forensics::FileSystemHandle fs;
  if (!fs.open(*m_tskImage, m_partition, error)) {
    emit completed({}, domain::op::failure("filesystem_open_failed", error, backend));
    return;
  }
  if (m_cancel->isCancellationRequested()) {
    emit completed({}, domain::op::cancelled(backend));
    return;
  }

  forensics::FileSystemBrowser browser;
  auto entries = browser.listDirectory(fs, m_path, error);
  auto resolved = detail::resolveDirectoryListOutcome(std::move(entries), error,
                                                      m_cancel->isCancellationRequested(), backend);
  if (resolved.second.succeeded() && isKnownUnsupportedOrUnconfirmedFs(m_partition.fileSystemType)) {
    resolved.second = domain::op::successWithWarning(
        backend,
        "filesystem_support_unconfirmed",
        QString("Filesystem %1 is not currently a supported target").arg(m_partition.fileSystemType),
        "Browsing is provided via generic TSK directory traversal and may be incomplete on this filesystem.");
  }
  emit completed(resolved.first, resolved.second);
}

ArtifactScanWorker::ArtifactScanWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                                       fie::domain::PartitionInfo partition)
    : m_tskImage(std::move(tskImage)), m_partition(std::move(partition)),
      m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void ArtifactScanWorker::requestCancel() { m_cancel->cancel(); }

void ArtifactScanWorker::process() {
  if (m_cancel->isCancellationRequested()) {
    emit completed({}, domain::op::cancelled());
    return;
  }

  if (!m_tskImage || !m_tskImage->isOpen()) {
    emit completed({}, domain::op::failure("image_not_open", "TSK image not open"));
    return;
  }
  const auto backend = domain::op::backendFromOpenAdapter(*m_tskImage);

  QString error;
  forensics::FileSystemHandle fs;
  if (!fs.open(*m_tskImage, m_partition, error)) {
    emit completed({}, domain::op::failure("filesystem_open_failed", error, backend));
    return;
  }

  forensics::FileSystemBrowser browser;
  forensics::ArtifactDiscoveryService discovery;
  QStringList warnings;
  auto artifacts = discovery.discover(
      m_partition,
      [&browser, &fs](const QString &path, QString &listError) {
        return browser.listDirectory(fs, path, listError);
      },
      warnings,
      [this]() { return m_cancel->isCancellationRequested(); });

  const auto resolved = detail::resolveArtifactDiscoveryOutcome(std::move(artifacts), warnings,
                                                               m_cancel->isCancellationRequested(), backend);
  emit completed(resolved.first, resolved.second);
}

ArtifactDetailWorker::ArtifactDetailWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                                           fie::domain::PartitionInfo partition,
                                           fie::domain::ArtifactRecord artifact)
    : m_tskImage(std::move(tskImage)),
      m_partition(std::move(partition)),
      m_artifact(std::move(artifact)),
      m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void ArtifactDetailWorker::requestCancel() { m_cancel->cancel(); }

void ArtifactDetailWorker::process() {
  domain::ArtifactRecord outArtifact = m_artifact;
  const QString cacheKey = QString("%1|%2")
                               .arg(m_partition.identifier.trimmed().toLower(),
                                    m_artifact.sourceLogicalPath.trimmed().toLower());
  if (m_cancel->isCancellationRequested()) {
    emit completed(cacheKey, outArtifact, domain::op::cancelled());
    return;
  }

  if (!m_tskImage || !m_tskImage->isOpen()) {
    emit completed(cacheKey, outArtifact, domain::op::failure("image_not_open", "TSK image not open"));
    return;
  }
  const auto backend = domain::op::backendFromOpenAdapter(*m_tskImage);

  forensics::ArtifactDetailService detailService;
  const auto parsed = detailService.describe(
      m_artifact,
      {
          [this](const QString &path, QString &readError) {
            if (m_cancel->isCancellationRequested()) {
              readError = "cancelled";
              return QByteArray();
            }
            QString error;
            forensics::FileSystemHandle fs;
            if (!fs.open(*m_tskImage, m_partition, error)) {
              readError = error;
              return QByteArray();
            }
            return forensics::readFileBytesByPath(fs, path, 1024 * 1024, readError);
          },
      });
  if (m_cancel->isCancellationRequested()) {
    emit completed(cacheKey, outArtifact, domain::op::cancelled(backend));
    return;
  }

  if (!parsed.has_value()) {
    outArtifact.details = std::nullopt;
    emit completed(cacheKey, outArtifact,
                   domain::op::success(backend, "artifact_detail_unsupported",
                                       "Parser-backed details are not available for this artifact type"));
    return;
  }
  outArtifact.details = parsed;

  if (parsed->state == domain::ArtifactParseState::Failed) {
    emit completed(cacheKey, outArtifact,
                   domain::op::successWithWarning(backend,
                                                  "artifact_detail_parse_failed",
                                                  "Artifact detail parse failed",
                                                  parsed->error.isEmpty() ? parsed->summary : parsed->error));
    return;
  }

  if (parsed->state == domain::ArtifactParseState::Partial) {
    emit completed(cacheKey, outArtifact,
                   domain::op::successWithWarning(backend,
                                                  "artifact_detail_partial",
                                                  "Artifact detail parse was partial",
                                                  parsed->warnings.join(" | ")));
    return;
  }

  emit completed(cacheKey, outArtifact,
                 domain::op::success(backend, "artifact_detail_parsed", "Artifact detail parsed"));
}

ArtifactAnalysisWorker::ArtifactAnalysisWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                                               fie::domain::PartitionInfo partition,
                                               std::vector<fie::domain::ArtifactRecord> artifacts)
    : m_tskImage(std::move(tskImage)),
      m_partition(std::move(partition)),
      m_artifacts(std::move(artifacts)),
      m_cancel(std::make_shared<forensics::CancellationToken>()) {}

void ArtifactAnalysisWorker::requestCancel() { m_cancel->cancel(); }

void ArtifactAnalysisWorker::process() {
  const QString contextKey = QString("%1|%2")
                                 .arg(m_partition.identifier.trimmed().toLower(),
                                      m_partition.fileSystemType.trimmed().toLower());
  if (m_cancel->isCancellationRequested()) {
    emit completed(contextKey, {}, domain::op::cancelled());
    return;
  }
  if (!m_tskImage || !m_tskImage->isOpen()) {
    emit completed(contextKey, {}, domain::op::failure("image_not_open", "TSK image not open"));
    return;
  }
  const auto backend = domain::op::backendFromOpenAdapter(*m_tskImage);

  QString fsError;
  forensics::FileSystemHandle fs;
  if (!fs.open(*m_tskImage, m_partition, fsError)) {
    emit completed(contextKey, {}, domain::op::failure("filesystem_open_failed", fsError, backend));
    return;
  }

  forensics::ArtifactDetailService detailService;
  const int total = static_cast<int>(m_artifacts.size());
  QStringList warnings;
  int processed = 0;
  for (auto &artifact : m_artifacts) {
    if (m_cancel->isCancellationRequested()) {
      emit completed(contextKey, {}, domain::op::cancelled(backend));
      return;
    }
    ++processed;
    emit progress(processed, total, artifact.sourceLogicalPath);

    if (artifact.status.compare("Present", Qt::CaseInsensitive) != 0 || artifact.directoryTarget) {
      continue;
    }

    const auto details = detailService.describe(
        artifact,
        {
            [&fs](const QString &path, QString &readError) {
              return readFileBytesByPath(fs, path, 1024 * 1024, readError);
            },
        });
    artifact.details = details;
    if (details.has_value() && details->state == domain::ArtifactParseState::Failed) {
      warnings.push_back(QString("%1: %2").arg(artifact.sourceLogicalPath, details->error));
    }
  }

  if (!warnings.isEmpty()) {
    emit completed(contextKey, std::move(m_artifacts),
                   domain::op::successWithWarning(backend,
                                                  "artifact_analysis_completed_with_warnings",
                                                  "Artifact analysis completed with warnings",
                                                  warnings.join(" | ")));
    return;
  }
  emit completed(contextKey, std::move(m_artifacts),
                 domain::op::success(backend, "artifact_analysis_completed", "Artifact analysis completed"));
}

} // namespace fie::workers

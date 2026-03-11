#include "ForensicImageExtractor/workers/ForensicsWorkers.h"

#include "ForensicImageExtractor/core/EwfSegmentResolver.h"
#include "ForensicImageExtractor/forensics/FileSystemHandle.h"
#include "ForensicImageExtractor/forensics/NtfsBrowser.h"
#include "ForensicImageExtractor/forensics/VolumeEnumerator.h"

namespace fie::workers {

ImageOpenWorker::ImageOpenWorker(std::shared_ptr<core::IImageReader> reader, QString path)
    : m_reader(std::move(reader)), m_path(std::move(path)) {}

void ImageOpenWorker::process() {
  QString error;
  fie::domain::ImageInfo info;
  const bool ok = m_reader && m_reader->open(m_path, error);
  if (ok) {
    info.path = m_path;
    info.sizeBytes = m_reader->size();
    info.format = fie::core::isEwfPath(m_path) ? "EWF" : "RAW/DD";
  }
  emit completed(ok, info, error);
}

PartitionScanWorker::PartitionScanWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage)
    : m_tskImage(std::move(tskImage)) {}

void PartitionScanWorker::process() {
  if (!m_tskImage) {
    emit completed({}, "TSK image adapter missing", {});
    return;
  }

  QString openError;
  if (!m_tskImage->open(openError)) {
    emit completed({}, openError, {});
    return;
  }

  forensics::VolumeEnumerator enumerator;
  QString error;
  const auto parts = enumerator.enumerate(*m_tskImage, error);
  const auto warning = m_tskImage->lastWarning();
  emit completed(parts, error, warning);
}

DirectoryListWorker::DirectoryListWorker(std::shared_ptr<core::TskImageHandleAdapter> tskImage,
                                         fie::domain::PartitionInfo partition,
                                         QString path)
    : m_tskImage(std::move(tskImage)), m_partition(std::move(partition)), m_path(std::move(path)) {}

void DirectoryListWorker::process() {
  if (!m_tskImage || !m_tskImage->isOpen()) {
    emit completed({}, "TSK image not open");
    return;
  }

  QString error;
  forensics::FileSystemHandle fs;
  if (!fs.open(*m_tskImage, m_partition, error)) {
    emit completed({}, error);
    return;
  }

  forensics::NtfsBrowser browser;
  auto entries = browser.listDirectory(fs, m_path, error);
  emit completed(entries, error);
}

} // namespace fie::workers

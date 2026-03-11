#include "ForensicImageExtractor/utils/MetadataFactory.h"

int runFileSystemMetadataModelTests() {
  fie::domain::ImageInfo image{.path = "img.dd"};
  fie::domain::PartitionInfo partition;
  partition.identifier = "p0";

  fie::domain::ExtractionResult genericResult;
  genericResult.source.name = "a.txt";
  genericResult.source.fullPath = "/a.txt";
  genericResult.source.metadata.ntfs.reset();

  const auto genericRecord = fie::utils::createCatalogRecord(image, partition, genericResult);
  if (genericRecord.siTimestamps.created.has_value() || genericRecord.fnTimestamps.created.has_value()) {
    return 1;
  }

  fie::domain::ExtractionResult ntfsResult;
  ntfsResult.source.name = "b.txt";
  ntfsResult.source.fullPath = "/b.txt";
  fie::domain::NtfsMetadata ntfs;
  ntfs.standardInfo.created = QDateTime::fromSecsSinceEpoch(10, Qt::UTC);
  ntfs.fileNameInfo.created = QDateTime::fromSecsSinceEpoch(20, Qt::UTC);
  ntfsResult.source.metadata.ntfs = ntfs;

  const auto ntfsRecord = fie::utils::createCatalogRecord(image, partition, ntfsResult);
  if (!ntfsRecord.siTimestamps.created.has_value() || !ntfsRecord.fnTimestamps.created.has_value()) {
    return 1;
  }

  fie::domain::FileSystemCapabilities caps;
  if (caps.supportsNtfsSiFnTimestamps || caps.supportsAds || !caps.supportsDeletedState || !caps.supportsStableFileId) {
    return 1;
  }

  return 0;
}

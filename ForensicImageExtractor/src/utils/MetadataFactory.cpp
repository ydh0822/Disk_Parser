#include "ForensicImageExtractor/utils/MetadataFactory.h"

namespace fie::utils {

domain::CatalogRecord createCatalogRecord(const domain::ImageInfo &image,
                                          const domain::PartitionInfo &partition,
                                          const domain::ExtractionResult &result) {
  domain::CatalogRecord r;
  r.sourceImagePath = image.path;
  r.partitionIdentifier = partition.identifier;
  r.logicalPath = result.source.fullPath;
  r.fileName = result.source.name;
  r.fileSize = result.source.sizeBytes;
  r.inode = result.source.inode;
  r.deleted = result.source.isDeleted;
  r.allocated = result.source.isAllocated;
  if (result.source.metadata.ntfs) {
    r.siTimestamps = result.source.metadata.ntfs->standardInfo;
    r.fnTimestamps = result.source.metadata.ntfs->fileNameInfo;
  }
  r.primaryOutcome = result.primaryOutcome;
  r.extractionStatus = result.status;
  r.destinationPath = result.destinationPath;
  r.sha256 = result.sha256;
  r.md5 = result.md5;
  r.error = result.error;
  r.warning = result.warning;
  r.bytesWritten = result.bytesWritten;
  r.hostTimestampsApplied = result.hostTimestampsApplied;
  r.hostTimestampError = result.hostTimestampError;
  return r;
}

} // namespace fie::utils

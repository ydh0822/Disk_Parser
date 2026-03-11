#include "ForensicImageExtractor/utils/MetadataFactory.h"

int runMetadataRecordTests() {
  fie::domain::ImageInfo image{.path = "a.dd"};
  fie::domain::PartitionInfo part;
  part.identifier = "p1";

  fie::domain::ExtractionResult result;
  result.source.name = "x";
  result.source.fullPath = "/x";
  result.status = "success";

  const auto rec = fie::utils::createCatalogRecord(image, part, result);
  return (rec.sourceImagePath == "a.dd" && rec.partitionIdentifier == "p1" && rec.fileName == "x") ? 0 : 1;
}

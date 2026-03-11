#pragma once

#include "ForensicImageExtractor/domain/Models.h"

namespace fie::utils {

domain::CatalogRecord createCatalogRecord(const domain::ImageInfo &image,
                                          const domain::PartitionInfo &partition,
                                          const domain::ExtractionResult &result);

}

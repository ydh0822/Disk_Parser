#include "ForensicImageExtractor/core/ImageReaderFactory.h"

#include "ForensicImageExtractor/core/EwfImageReader.h"
#include "ForensicImageExtractor/core/EwfSegmentResolver.h"
#include "ForensicImageExtractor/core/RawImageReader.h"

namespace fie::core {

std::unique_ptr<IImageReader> ImageReaderFactory::create(const QString &imagePath) {
  if (isEwfPath(imagePath)) {
    return std::make_unique<EwfImageReader>();
  }
  return std::make_unique<RawImageReader>();
}

} // namespace fie::core

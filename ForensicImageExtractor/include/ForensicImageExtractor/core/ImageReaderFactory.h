#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

#include <memory>

namespace fie::core {

class ImageReaderFactory {
public:
  static std::unique_ptr<IImageReader> create(const QString &imagePath);
};

} // namespace fie::core

#include "ForensicImageExtractor/core/EwfImageReader.h"
#include "ForensicImageExtractor/core/ImageReaderFactory.h"
#include "ForensicImageExtractor/core/RawImageReader.h"

int runImageReaderFactoryRoutingTests() {
  auto r1 = fie::core::ImageReaderFactory::create("a.E02");
  if (!dynamic_cast<fie::core::EwfImageReader *>(r1.get())) return 1;

  auto r2 = fie::core::ImageReaderFactory::create("a.EX02");
  if (!dynamic_cast<fie::core::EwfImageReader *>(r2.get())) return 1;

  auto r3 = fie::core::ImageReaderFactory::create("a.S01");
  if (!dynamic_cast<fie::core::EwfImageReader *>(r3.get())) return 1;

  auto r4 = fie::core::ImageReaderFactory::create("a.dd");
  if (!dynamic_cast<fie::core::RawImageReader *>(r4.get())) return 1;

  return 0;
}

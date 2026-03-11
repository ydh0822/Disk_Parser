#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

#include <memory>

struct TSK_IMG_INFO;

namespace fie::core {

class ITskReaderBridge {
public:
  virtual ~ITskReaderBridge() = default;
  virtual bool openFromReader(const std::shared_ptr<IImageReader> &reader, TSK_IMG_INFO *&out,
                              QString &error) = 0;
  virtual void close(TSK_IMG_INFO *img) = 0;
  virtual bool isImplemented() const = 0;
};

class TskReaderBridgeScaffold final : public ITskReaderBridge {
public:
  bool openFromReader(const std::shared_ptr<IImageReader> &reader, TSK_IMG_INFO *&out,
                      QString &error) override;
  void close(TSK_IMG_INFO *img) override;
  bool isImplemented() const override;
};

} // namespace fie::core

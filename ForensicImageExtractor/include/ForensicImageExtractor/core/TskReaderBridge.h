#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

#include <memory>

namespace fie::core {
class ReadCache;
}



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

struct ReaderBridgeState {
  std::shared_ptr<IImageReader> reader;
  std::unique_ptr<ReadCache> cache;
  quint64 size{0};
  bool closed{false};
};

class TskReaderBridgeScaffold final : public ITskReaderBridge {
public:
  bool openFromReader(const std::shared_ptr<IImageReader> &reader, TSK_IMG_INFO *&out,
                      QString &error) override;
  void close(TSK_IMG_INFO *img) override;
  bool isImplemented() const override;

  // Testing hooks for callback semantics independent of TSK runtime availability.
  static std::unique_ptr<ReaderBridgeState> createStateForTesting(const std::shared_ptr<IImageReader> &reader,
                                                                  QString &error);
  static qint64 readFromStateForTesting(ReaderBridgeState &state, quint64 offset, char *buf, quint64 len,
                                        QString &error);
  static void closeStateForTesting(ReaderBridgeState &state);
};

} // namespace fie::core

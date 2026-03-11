#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

#include <memory>

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

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

class TskReaderBridge final : public ITskReaderBridge {
public:
  bool openFromReader(const std::shared_ptr<IImageReader> &reader, TSK_IMG_INFO *&out,
                      QString &error) override;
  void close(TSK_IMG_INFO *img) override;
  bool isImplemented() const override;

  // Test hooks for callback semantics independent of full TSK filesystem flows.
  static std::unique_ptr<ReaderBridgeState> createStateForTest(const std::shared_ptr<IImageReader> &reader,
                                                               QString &error);
  static qint64 readFromStateForTest(ReaderBridgeState &state, quint64 offset, char *buf, quint64 len,
                                     QString &error);
  static void closeStateForTest(ReaderBridgeState &state);

private:
#if defined(FIE_HAS_TSK)
  static ssize_t tskReadCallback(TSK_IMG_INFO *img, TSK_OFF_T off, char *buf, size_t len);
  static void tskCloseCallback(TSK_IMG_INFO *img);
#endif
};

} // namespace fie::core

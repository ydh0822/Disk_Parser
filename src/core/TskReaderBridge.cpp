#include "ForensicImageExtractor/core/TskReaderBridge.h"

#include "ForensicImageExtractor/core/ReadCache.h"
#include "ForensicImageExtractor/core/TskExternalImageApi.h"

#include <cstring>
#include <limits>

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::core {

bool TskReaderBridge::openFromReader(const std::shared_ptr<IImageReader> &reader,
                                     TSK_IMG_INFO *&out,
                                     QString &error) {
  out = nullptr;
#if defined(FIE_HAS_TSK)
  auto state = createStateForTest(reader, error);
  if (!state) {
    return false;
  }

  auto *rawState = state.release();
  TSK_IMG_INFO *img = TskExternalImageApi::openExternal(rawState->size, rawState,
                                                        &TskReaderBridge::tskReadCallback,
                                                        &TskReaderBridge::tskCloseCallback, error);
  if (!img) {
    delete rawState;
    return false;
  }

  out = img;
  return true;
#else
  Q_UNUSED(reader)
  error = "Reader-backed TSK bridge is unavailable because TSK support is not enabled in this build";
  return false;
#endif
}

void TskReaderBridge::close(TSK_IMG_INFO *img) {
#if defined(FIE_HAS_TSK)
  if (img) {
    tsk_img_close(img);
  }
#else
  Q_UNUSED(img)
#endif
}

bool TskReaderBridge::isImplemented() const {
#if defined(FIE_HAS_TSK)
  return true;
#else
  return false;
#endif
}

std::unique_ptr<ReaderBridgeState> TskReaderBridge::createStateForTest(
    const std::shared_ptr<IImageReader> &reader,
    QString &error) {
  if (!reader || !reader->isOpen()) {
    error = "Reader bridge state requires an open reader";
    return nullptr;
  }

  auto state = std::make_unique<ReaderBridgeState>();
  state->reader = reader;
  state->size = reader->size();
  state->cache = std::make_unique<ReadCache>(reader);
  return state;
}

qint64 TskReaderBridge::readFromStateForTest(ReaderBridgeState &state,
                                             quint64 offset,
                                             char *buf,
                                             quint64 len,
                                             QString &error) {
  if (state.closed) {
    error = "Reader bridge state is closed";
    return -1;
  }
  if (!buf) {
    error = "Read buffer is null";
    return -1;
  }
  if (!state.cache) {
    error = "Reader bridge cache is unavailable";
    return -1;
  }
  if (offset >= state.size) {
    return 0;
  }

  const quint64 safeLen = std::min(len, state.size - offset);
  const QByteArray data = state.cache->read(offset, safeLen, error);
  if (!error.isEmpty()) {
    return -1;
  }
  if (data.isEmpty()) {
    return 0;
  }

  std::memcpy(buf, data.constData(), static_cast<size_t>(data.size()));
  return static_cast<qint64>(data.size());
}

void TskReaderBridge::closeStateForTest(ReaderBridgeState &state) {
  state.closed = true;
  if (state.cache) {
    state.cache->clear();
  }
}

#if defined(FIE_HAS_TSK)
ssize_t TskReaderBridge::tskReadCallback(TSK_IMG_INFO *img, TSK_OFF_T off, char *buf, size_t len) {
  if (!img || !buf || off < 0) {
    return -1;
  }

  auto *state = static_cast<ReaderBridgeState *>(img->impl);
  if (!state) {
    return -1;
  }

  if (len > static_cast<size_t>(std::numeric_limits<quint64>::max())) {
    return -1;
  }

  QString error;
  const qint64 read = readFromStateForTest(*state, static_cast<quint64>(off), buf, static_cast<quint64>(len), error);
  if (read < 0) {
    if (!error.isEmpty()) {
      TskExternalImageApi::setReadError(error);
    }
    return -1;
  }

  if (read > static_cast<qint64>(std::numeric_limits<ssize_t>::max())) {
    TskExternalImageApi::setReadError("Reader-backed TSK bridge read exceeds ssize_t return range");
    return -1;
  }

  return static_cast<ssize_t>(read);
}

void TskReaderBridge::tskCloseCallback(TSK_IMG_INFO *img) {
  if (!img) {
    return;
  }

  auto *state = static_cast<ReaderBridgeState *>(img->impl);
  if (state) {
    closeStateForTest(*state);
    delete state;
    img->impl = nullptr;
  }
}
#endif

} // namespace fie::core

#include "ForensicImageExtractor/core/TskReaderBridge.h"

#include "ForensicImageExtractor/core/ReadCache.h"

#include <cstring>

namespace fie::core {

bool TskReaderBridgeScaffold::openFromReader(const std::shared_ptr<IImageReader> &reader,
                                             TSK_IMG_INFO *&out,
                                             QString &error) {
  Q_UNUSED(reader)
  out = nullptr;
  error = "Reader-backed TSK bridge scaffold present but callback image implementation is not complete yet";
  return false;
}

void TskReaderBridgeScaffold::close(TSK_IMG_INFO *img) { Q_UNUSED(img) }

bool TskReaderBridgeScaffold::isImplemented() const { return false; }

std::unique_ptr<ReaderBridgeState> TskReaderBridgeScaffold::createStateForTesting(
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

qint64 TskReaderBridgeScaffold::readFromStateForTesting(ReaderBridgeState &state,
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

void TskReaderBridgeScaffold::closeStateForTesting(ReaderBridgeState &state) {
  state.closed = true;
  if (state.cache) {
    state.cache->clear();
  }
}

} // namespace fie::core

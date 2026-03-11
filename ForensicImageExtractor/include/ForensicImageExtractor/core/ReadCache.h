#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

#include <QHash>
#include <QList>

#include <memory>

namespace fie::core {

class ReadCache {
public:
  struct Stats {
    quint64 hits{0};
    quint64 misses{0};
  };

  explicit ReadCache(std::shared_ptr<IImageReader> reader, quint64 blockSize = 1024 * 1024,
                     int maxBlocks = 64);

  QByteArray read(quint64 offset, quint64 size, QString &error);
  void clear();
  Stats stats() const;

private:
  QByteArray readBlock(quint64 blockIndex, QString &error);
  void touchLru(quint64 blockIndex);

  std::shared_ptr<IImageReader> m_reader;
  quint64 m_blockSize{0};
  int m_maxBlocks{0};
  QHash<quint64, QByteArray> m_blocks;
  QList<quint64> m_lru;
  Stats m_stats;
};

} // namespace fie::core

#include "ForensicImageExtractor/core/ReadCache.h"

#include <algorithm>

namespace fie::core {

ReadCache::ReadCache(std::shared_ptr<IImageReader> reader, quint64 blockSize, int maxBlocks)
    : m_reader(std::move(reader)), m_blockSize(std::max<quint64>(1, blockSize)),
      m_maxBlocks(std::max(1, maxBlocks)) {}

QByteArray ReadCache::read(quint64 offset, quint64 size, QString &error) {
  QByteArray out;
  if (!m_reader || !m_reader->isOpen()) {
    error = "Reader is not open";
    return out;
  }
  if (size == 0) {
    return out;
  }

  out.reserve(static_cast<qsizetype>(size));
  quint64 remaining = size;
  quint64 cursor = offset;
  while (remaining > 0) {
    const quint64 blockIdx = cursor / m_blockSize;
    const quint64 inBlockOffset = cursor % m_blockSize;
    const QByteArray block = readBlock(blockIdx, error);
    if (!error.isEmpty()) {
      return {};
    }
    if (block.isEmpty() || inBlockOffset >= static_cast<quint64>(block.size())) {
      break;
    }

    const quint64 available = static_cast<quint64>(block.size()) - inBlockOffset;
    const quint64 take = std::min(remaining, available);
    out.append(block.constData() + static_cast<qsizetype>(inBlockOffset), static_cast<qsizetype>(take));

    cursor += take;
    remaining -= take;

    if (take < available) {
      continue;
    }
    if (static_cast<quint64>(block.size()) < m_blockSize) {
      break;
    }
  }
  return out;
}

void ReadCache::clear() {
  m_blocks.clear();
  m_lru.clear();
}

ReadCache::Stats ReadCache::stats() const { return m_stats; }

QByteArray ReadCache::readBlock(quint64 blockIndex, QString &error) {
  if (m_blocks.contains(blockIndex)) {
    ++m_stats.hits;
    touchLru(blockIndex);
    return m_blocks.value(blockIndex);
  }

  ++m_stats.misses;
  const quint64 start = blockIndex * m_blockSize;
  QByteArray block = m_reader->read(start, m_blockSize, error);
  if (!error.isEmpty()) {
    return {};
  }

  m_blocks.insert(blockIndex, block);
  touchLru(blockIndex);

  while (m_lru.size() > m_maxBlocks) {
    const quint64 evict = m_lru.takeLast();
    m_blocks.remove(evict);
  }

  return block;
}

void ReadCache::touchLru(quint64 blockIndex) {
  m_lru.removeAll(blockIndex);
  m_lru.prepend(blockIndex);
}

} // namespace fie::core

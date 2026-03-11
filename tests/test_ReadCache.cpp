#include "ForensicImageExtractor/core/ReadCache.h"

class CountingReader final : public fie::core::IImageReader {
public:
  bool open(const QString &imagePath, QString &error) override {
    Q_UNUSED(imagePath)
    Q_UNUSED(error)
    m_open = true;
    return true;
  }
  void close() override { m_open = false; }
  QByteArray read(quint64 offset, quint64 size, QString &error) override {
    Q_UNUSED(error)
    ++readCalls;
    QByteArray out;
    for (quint64 i = 0; i < size && offset + i < static_cast<quint64>(m_data.size()); ++i) {
      out.push_back(m_data[static_cast<int>(offset + i)]);
    }
    return out;
  }
  quint64 size() const override { return static_cast<quint64>(m_data.size()); }
  bool isOpen() const override { return m_open; }
  QString path() const override { return "fake"; }

  QByteArray m_data{"abcdefghijklmnopqrstuvwxyz"};
  int readCalls{0};
  bool m_open{true};
};

int runReadCacheTests() {
  auto reader = std::make_shared<CountingReader>();
  fie::core::ReadCache cache(reader, 8, 4);

  QString error;
  const auto first = cache.read(2, 10, error);
  if (!error.isEmpty() || first != "cdefghijkl") {
    return 1;
  }

  const int callsAfterFirst = reader->readCalls;
  const auto second = cache.read(3, 4, error);
  if (!error.isEmpty() || second != "defg") {
    return 1;
  }

  if (reader->readCalls != callsAfterFirst) {
    return 1;
  }

  const auto stats = cache.stats();
  if (stats.hits == 0 || stats.misses == 0) {
    return 1;
  }

  return 0;
}

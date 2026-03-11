#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/core/TskReaderBridge.h"

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

#include <QDir>
#include <QFile>
#include <cstring>

class BridgeFakeReader final : public fie::core::IImageReader {
public:
  bool open(const QString &imagePath, QString &error) override {
    Q_UNUSED(error)
    m_open = true;
    m_path = imagePath;
    return true;
  }
  void close() override {
    m_open = false;
    ++closeCalls;
  }
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
  QString path() const override { return m_path; }

  QByteArray m_data{"0123456789abcdefghijklmnopqrstuvwxyz"};
  QString m_path{"fake.e01"};
  bool m_open{true};
  int readCalls{0};
  int closeCalls{0};
};

class AlwaysFailBridge final : public fie::core::ITskReaderBridge {
public:
  bool openFromReader(const std::shared_ptr<fie::core::IImageReader> &, TSK_IMG_INFO *&out, QString &error) override {
    out = nullptr;
    error = "Injected bridge failure";
    return false;
  }
  void close(TSK_IMG_INFO *img) override { Q_UNUSED(img) }
  bool isImplemented() const override { return true; }
};

int runTskReaderBridgeTests() {
  auto reader = std::make_shared<BridgeFakeReader>();

  QString error;
  auto state = fie::core::TskReaderBridge::createStateForTest(reader, error);
  if (!state || !error.isEmpty()) {
    return 1;
  }
  if (state->size != static_cast<quint64>(reader->m_data.size())) {
    return 1;
  }

  char buf[7] = {0};
  const qint64 firstRead = fie::core::TskReaderBridge::readFromStateForTest(*state, 5, buf, 6, error);
  if (!error.isEmpty() || firstRead != 6 || std::memcmp(buf, "56789a", 6) != 0) {
    return 1;
  }

  const qint64 secondRead =
      fie::core::TskReaderBridge::readFromStateForTest(*state, reader->size() - 2, buf, 6, error);
  if (!error.isEmpty() || secondRead != 2 || std::memcmp(buf, "yz", 2) != 0) {
    return 1;
  }

  fie::core::TskReaderBridge::closeStateForTest(*state);
  if (!state->closed) {
    return 1;
  }

  error.clear();
  const qint64 readAfterClose = fie::core::TskReaderBridge::readFromStateForTest(*state, 0, buf, 2, error);
  if (readAfterClose >= 0 || error.isEmpty()) {
    return 1;
  }

#if defined(FIE_HAS_TSK)
  // Bridge-level integration: open a real TSK external image and read via tsk_img_read.
  fie::core::TskReaderBridge bridge;
  TSK_IMG_INFO *img = nullptr;
  error.clear();
  if (!bridge.openFromReader(reader, img, error) || !img) {
    return 1;
  }

  char integrationBuf[8] = {0};
  const ssize_t integrationRead = tsk_img_read(img, 4, integrationBuf, 7);
  if (integrationRead != 7 || std::memcmp(integrationBuf, "456789a", 7) != 0) {
    bridge.close(img);
    return 1;
  }
  bridge.close(img);

  // Adapter-level fallback semantics through an injected failing bridge.
  const QString fallbackPath = QDir::currentPath() + "/.bridge-fallback-test.img";
  {
    QFile f(fallbackPath);
    if (!f.open(QIODevice::WriteOnly)) {
      return 1;
    }
    f.write("fallback-data");
    f.close();
  }

  auto fallbackReader = std::make_shared<BridgeFakeReader>();
  fallbackReader->m_path = fallbackPath;
  fie::core::TskImageHandleAdapter fallbackAdapter(fallbackReader, std::make_unique<AlwaysFailBridge>());
  error.clear();
  const bool fallbackOpened = fallbackAdapter.open(error);
  QFile::remove(fallbackPath);
  if (!fallbackOpened || !error.isEmpty() || fallbackAdapter.backend() != fie::core::TskOpenBackend::PathBased ||
      fallbackAdapter.lastWarning().isEmpty()) {
    return 1;
  }

  auto failReader = std::make_shared<BridgeFakeReader>();
  failReader->m_path = QDir::currentPath() + "/definitely_missing_bridge_fallback.img";
  fie::core::TskImageHandleAdapter failAdapter(failReader, std::make_unique<AlwaysFailBridge>());
  error.clear();
  if (failAdapter.open(error) || error.isEmpty()) {
    return 1;
  }
#endif

  const auto fallbackWarn = fie::core::TskImageHandleAdapter::resolveOpenOutcomeForTesting(
      "Reader-backed bridge failed", true, "");
  if (!fallbackWarn.success || fallbackWarn.backend != fie::core::TskOpenBackend::PathBased ||
      fallbackWarn.warning.isEmpty() || !fallbackWarn.error.isEmpty()) {
    return 1;
  }

  const auto hardError = fie::core::TskImageHandleAdapter::resolveOpenOutcomeForTesting(
      "Reader-backed bridge failed", false, "Path-based open failed");
  if (hardError.success || hardError.error.isEmpty()) {
    return 1;
  }

  return 0;
}

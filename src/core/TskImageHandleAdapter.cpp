#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"

#include "ForensicImageExtractor/core/TskReaderBridge.h"

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::core {

TskImageHandleAdapter::TskImageHandleAdapter(std::shared_ptr<IImageReader> reader)
    : m_reader(std::move(reader)), m_readerBridge(std::make_unique<TskReaderBridge>()) {}

TskImageHandleAdapter::TskImageHandleAdapter(std::shared_ptr<IImageReader> reader,
                                             std::unique_ptr<ITskReaderBridge> readerBridge)
    : m_reader(std::move(reader)), m_readerBridge(std::move(readerBridge)) {}

TskImageHandleAdapter::~TskImageHandleAdapter() { close(); }

TskOpenResolution TskImageHandleAdapter::resolveOpenOutcomeForTesting(const QString &readerBridgeMessage,
                                                                      bool pathOpenSucceeded,
                                                                      const QString &pathErrorMessage) {
  TskOpenResolution out;
  if (pathOpenSucceeded) {
    out.success = true;
    out.backend = TskOpenBackend::PathBased;
    out.warning = readerBridgeMessage;
    return out;
  }

  out.success = false;
  out.backend = TskOpenBackend::PathBased;
  out.error = readerBridgeMessage;
  if (!pathErrorMessage.isEmpty()) {
    out.error = out.error + (out.error.isEmpty() ? "" : " | ") + pathErrorMessage;
  }
  return out;
}

bool TskImageHandleAdapter::open(QString &error) {
  close();
  m_lastWarning.clear();
  if (!m_reader || !m_reader->isOpen()) {
    error = "Image reader is not open";
    return false;
  }

  if (openReaderBridge(error)) {
    m_backend = TskOpenBackend::ReaderBridge;
    return true;
  }

  QString pathError;
  const bool pathOpened = openPathBased(pathError);
  const auto resolved = resolveOpenOutcomeForTesting(error, pathOpened, pathError);
  m_backend = resolved.backend;
  m_lastWarning = resolved.warning;
  error = resolved.error;
  return resolved.success;
}

bool TskImageHandleAdapter::openReaderBridge(QString &error) {
  if (!m_readerBridge) {
    error = "Reader-backed bridge factory unavailable";
    return false;
  }

  TSK_IMG_INFO *bridgeImg = nullptr;
  if (!m_readerBridge->openFromReader(m_reader, bridgeImg, error)) {
    return false;
  }

  m_img = bridgeImg;
  return true;
}

bool TskImageHandleAdapter::openPathBased(QString &error) {
#if defined(FIE_HAS_TSK)
  const auto path = m_reader->path().toUtf8();
  const char *images[] = {path.constData()};
  m_img = tsk_img_open_utf8(1, images, TSK_IMG_TYPE_DETECT, 0);
  if (!m_img) {
    error = QString("TSK path-based image open failed: %1").arg(tsk_error_get());
    return false;
  }
  return true;
#else
  error = "TSK support is unavailable at build time";
  return false;
#endif
}

void TskImageHandleAdapter::close() {
#if defined(FIE_HAS_TSK)
  if (m_img) {
    if (m_backend == TskOpenBackend::ReaderBridge && m_readerBridge) {
      m_readerBridge->close(m_img);
    } else {
      tsk_img_close(m_img);
    }
    m_img = nullptr;
  }
#endif
  m_backend = TskOpenBackend::PathBased;
  m_lastWarning.clear();
}

bool TskImageHandleAdapter::isOpen() const { return m_img != nullptr; }
TSK_IMG_INFO *TskImageHandleAdapter::img() const { return m_img; }
TskOpenBackend TskImageHandleAdapter::backend() const { return m_backend; }
bool TskImageHandleAdapter::isReaderBridgeReady() const {
  return m_readerBridge ? m_readerBridge->isImplemented() : false;
}
QString TskImageHandleAdapter::lastWarning() const { return m_lastWarning; }

} // namespace fie::core

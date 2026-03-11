#include "ForensicImageExtractor/core/TskExternalImageApi.h"

#include <QByteArray>
#include <limits>

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::core {

TSK_IMG_INFO *TskExternalImageApi::openExternal(quint64 imageSize,
                                                void *impl,
#if defined(FIE_HAS_TSK)
                                                ReadCallback readCb,
                                                CloseCallback closeCb,
#endif
                                                QString &error) {
#if defined(FIE_HAS_TSK)
  if (imageSize > static_cast<quint64>(std::numeric_limits<TSK_OFF_T>::max())) {
    error = "Reader-backed TSK bridge failed: image size exceeds TSK offset range";
    return nullptr;
  }
  TSK_IMG_INFO *img = tsk_img_open_external(static_cast<TSK_OFF_T>(imageSize), 0, impl, readCb, closeCb);
  if (!img) {
    error = QString("Reader-backed TSK bridge failed to initialize external image: %1").arg(tsk_error_get());
  }
  return img;
#else
  Q_UNUSED(imageSize)
  Q_UNUSED(impl)
  error = "Reader-backed TSK bridge is unavailable because TSK support is not enabled in this build";
  return nullptr;
#endif
}

void TskExternalImageApi::setReadError(const QString &error) {
#if defined(FIE_HAS_TSK)
  const QByteArray utf8 = error.toUtf8();
  tsk_error_reset();
  tsk_error_set_errno(TSK_ERR_IMG_READ);
  tsk_error_set_errstr("%s", utf8.constData());
#else
  Q_UNUSED(error)
#endif
}

} // namespace fie::core

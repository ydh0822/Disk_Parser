#pragma once

#include <QString>

struct TSK_IMG_INFO;

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::core {

class TskExternalImageApi {
public:
#if defined(FIE_HAS_TSK)
  using ReadCallback = ssize_t (*)(TSK_IMG_INFO *, TSK_OFF_T, char *, size_t);
  using CloseCallback = void (*)(TSK_IMG_INFO *);
#endif

  static TSK_IMG_INFO *openExternal(quint64 imageSize, void *impl,
#if defined(FIE_HAS_TSK)
                                    ReadCallback readCb, CloseCallback closeCb,
#endif
                                    QString &error);

  static void setReadError(const QString &error);
};

} // namespace fie::core

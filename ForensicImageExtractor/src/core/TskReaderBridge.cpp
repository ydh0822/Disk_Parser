#include "ForensicImageExtractor/core/TskReaderBridge.h"

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

} // namespace fie::core

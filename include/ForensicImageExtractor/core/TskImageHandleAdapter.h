#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"

#include <memory>

struct TSK_IMG_INFO;

namespace fie::core {

class ITskReaderBridge;

enum class TskOpenBackend {
  ReaderBridge,
  PathBased,
};

struct TskOpenResolution {
  bool success{false};
  QString error;
  QString warning;
  TskOpenBackend backend{TskOpenBackend::PathBased};
};

class TskImageHandleAdapter {
public:
  explicit TskImageHandleAdapter(std::shared_ptr<IImageReader> reader, bool allowPathFallback = false);
  TskImageHandleAdapter(std::shared_ptr<IImageReader> reader, std::unique_ptr<ITskReaderBridge> readerBridge,
                        bool allowPathFallback);
  ~TskImageHandleAdapter();

  bool open(QString &error);
  void close();
  bool isOpen() const;
  TSK_IMG_INFO *img() const;
  TskOpenBackend backend() const;
  bool isReaderBridgeReady() const;
  QString lastWarning() const;
  bool isPathFallbackEnabled() const;

  static TskOpenResolution resolveOpenOutcomeForTesting(const QString &readerBridgeMessage,
                                                        bool pathOpenSucceeded,
                                                        const QString &pathErrorMessage);

private:
  bool openPathBased(QString &error);
  bool openReaderBridge(QString &error);

  std::shared_ptr<IImageReader> m_reader;
  std::unique_ptr<ITskReaderBridge> m_readerBridge;
  bool m_allowPathFallback{false};
  TSK_IMG_INFO *m_img{nullptr};
  TskOpenBackend m_backend{TskOpenBackend::PathBased};
  QString m_lastWarning;
};

} // namespace fie::core

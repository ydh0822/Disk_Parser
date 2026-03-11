#pragma once

#include <QMetaType>
#include <QString>

#include <atomic>
#include <functional>
#include <memory>

namespace fie::forensics {

class CancellationToken {
public:
  void cancel() { m_cancelled.store(true); }
  bool isCancellationRequested() const { return m_cancelled.load(); }

private:
  std::atomic_bool m_cancelled{false};
};

struct ProgressInfo {
  QString currentPath;
  int currentFileIndex{0};
  int totalFiles{0};
  quint64 fileBytesProcessed{0};
  quint64 fileBytesTotal{0};
  quint64 totalBytesProcessed{0};
  quint64 totalBytesEstimated{0};
};

struct TaskContext {
  std::shared_ptr<CancellationToken> cancellation;
  std::function<void(const ProgressInfo &)> onProgress;

  bool isCancellationRequested() const {
    return cancellation && cancellation->isCancellationRequested();
  }
};

} // namespace fie::forensics

Q_DECLARE_METATYPE(fie::forensics::ProgressInfo)

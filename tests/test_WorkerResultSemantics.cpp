#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/ForensicOperationResultUtils.h"
#include "ForensicImageExtractor/workers/ExtractionWorker.h"
#include "ForensicImageExtractor/workers/ForensicsWorkers.h"
#include "workers/WorkerOutcomePolicy.h"

class SemanticsFakeReader final : public fie::core::IImageReader {
public:
  bool open(const QString &, QString &) override {
    m_open = true;
    return true;
  }
  void close() override { m_open = false; }
  QByteArray read(quint64, quint64, QString &) override { return {}; }
  quint64 size() const override { return 0; }
  bool isOpen() const override { return m_open; }
  QString path() const override { return "synthetic.e01"; }

private:
  bool m_open{true};
};

class AlwaysFailBridge final : public fie::core::ITskReaderBridge {
public:
  bool openFromReader(const std::shared_ptr<fie::core::IImageReader> &, TSK_IMG_INFO *&out,
                      QString &error) override {
    out = nullptr;
    error = "Reader-backed open failed";
    return false;
  }
  void close(TSK_IMG_INFO *) override {}
  bool isImplemented() const override { return true; }
};

int runWorkerResultSemanticsTests() {
  // TSK adapter open failure without fallback should report ReaderBridge backend.
  {
    auto reader = std::make_shared<SemanticsFakeReader>();
    auto adapter = std::make_shared<fie::core::TskImageHandleAdapter>(reader, std::make_unique<AlwaysFailBridge>(), false);
    fie::workers::PartitionScanWorker worker(adapter);

    bool called = false;
    QObject::connect(&worker, &fie::workers::PartitionScanWorker::completed,
                     [&](std::vector<fie::domain::PartitionInfo>, fie::domain::ForensicOperationResult result) {
                       called = result.state == fie::domain::ForensicOperationState::Failure &&
                                result.diagnostic.reason == "tsk_image_open_failed" &&
                                result.backend == fie::domain::ForensicBackend::ReaderBridge;
                     });
    worker.process();
    if (!called) return 1;
  }

  // TSK adapter open failure with fallback allowed remains backend-ambiguous => Unknown.
  {
    auto reader = std::make_shared<SemanticsFakeReader>();
    auto adapter = std::make_shared<fie::core::TskImageHandleAdapter>(reader, std::make_unique<AlwaysFailBridge>(), true);
    fie::workers::PartitionScanWorker worker(adapter);

    bool called = false;
    QObject::connect(&worker, &fie::workers::PartitionScanWorker::completed,
                     [&](std::vector<fie::domain::PartitionInfo>, fie::domain::ForensicOperationResult result) {
                       called = result.state == fie::domain::ForensicOperationState::Failure &&
                                result.diagnostic.reason == "tsk_image_open_failed" &&
                                result.backend == fie::domain::ForensicBackend::Unknown;
                     });
    worker.process();
    if (!called) return 1;
  }

  // Immediate cancellation semantics remain deterministic and suppress payloads.
  {
    fie::workers::DirectoryListWorker worker(nullptr, {}, "/");
    worker.requestCancel();
    bool called = false;
    QObject::connect(&worker, &fie::workers::DirectoryListWorker::completed,
                     [&](std::vector<fie::domain::FileEntry> entries, fie::domain::ForensicOperationResult result) {
                       called = entries.empty() && result.state == fie::domain::ForensicOperationState::Failure &&
                                result.diagnostic.reason == "cancelled";
                     });
    worker.process();
    if (!called) return 1;
  }

  {
    fie::workers::ArtifactScanWorker worker(nullptr, {});
    worker.requestCancel();
    bool called = false;
    QObject::connect(&worker, &fie::workers::ArtifactScanWorker::completed,
                     [&](std::vector<fie::domain::ArtifactRecord> artifacts, fie::domain::ForensicOperationResult result) {
                       called = artifacts.empty() && result.state == fie::domain::ForensicOperationState::Failure &&
                                result.diagnostic.reason == "cancelled";
                     });
    worker.process();
    if (!called) return 1;
  }

  {
    fie::domain::ExtractionTask task;
    fie::workers::ExtractionWorker worker(nullptr, task);
    worker.requestCancel();
    bool called = false;
    QObject::connect(&worker, &fie::workers::ExtractionWorker::completed,
                     [&](std::vector<fie::domain::ExtractionResult> results,
                         fie::domain::ForensicOperationResult result) {
                       called = results.empty() && result.state == fie::domain::ForensicOperationState::Failure &&
                                result.diagnostic.reason == "cancelled";
                     });
    worker.process();
    if (!called) return 1;
  }

  // Post-call cancellation policy: suppress payloads after long-running call returns.
  {
    std::vector<fie::domain::FileEntry> entries(2);
    const auto out = fie::workers::detail::resolveDirectoryListOutcome(
        entries, QString(), true, fie::domain::ForensicBackend::ReaderBridge);
    if (!out.first.empty() || out.second.diagnostic.reason != "cancelled") return 1;
  }

  {
    std::vector<fie::domain::ArtifactRecord> artifacts(3);
    const auto out = fie::workers::detail::resolveArtifactDiscoveryOutcome(
        artifacts, {"first warning", "second warning"}, true, fie::domain::ForensicBackend::PathFallback);
    if (!out.first.empty() || out.second.diagnostic.reason != "cancelled") return 1;
  }

  {
    std::vector<fie::domain::ExtractionResult> results(1);
    const auto out = fie::workers::detail::resolveExtractionOutcome(
        results, QString(), true, fie::domain::ForensicBackend::ReaderBridge);
    if (!out.first.empty() || out.second.diagnostic.reason != "cancelled") return 1;
  }

  // Warning detail propagation is explicit and non-structured (opaque diagnostic text).
  {
    const auto out = fie::workers::detail::resolveArtifactDiscoveryOutcome(
        {}, {"a", "b"}, false, fie::domain::ForensicBackend::ReaderBridge);
    if (out.second.state != fie::domain::ForensicOperationState::SuccessWithWarning) return 1;
    if (out.second.diagnostic.reason != "artifact_scan_with_warnings") return 1;
    if (out.second.diagnostic.detail != "a || b") return 1;
  }

  // Extraction warning paths keep payload and return SuccessWithWarning.
  {
    fie::domain::ExtractionResult res;
    res.warning = "short_read";
    std::vector<fie::domain::ExtractionResult> results{res};
    const auto out = fie::workers::detail::resolveExtractionOutcome(
        std::move(results), QString(), false, fie::domain::ForensicBackend::ReaderBridge);
    if (out.first.size() != 1 || out.second.state != fie::domain::ForensicOperationState::SuccessWithWarning) {
      return 1;
    }
    if (out.second.diagnostic.reason != "extraction_completed_with_warnings") return 1;
  }

  // Directory error mapping after post-call check remains deterministic.
  {
    const auto out = fie::workers::detail::resolveDirectoryListOutcome(
        {}, "list failed", false, fie::domain::ForensicBackend::ReaderBridge);
    if (!out.first.empty() || out.second.diagnostic.reason != "directory_list_failed") return 1;
  }

  // Fallback-success semantics remain success-with-warning + PathBased in adapter resolution helper.
  {
    const auto resolved = fie::core::TskImageHandleAdapter::resolveOpenOutcomeForTesting(
        "Reader-backed unavailable", true, "");
    if (!resolved.success || resolved.warning.isEmpty() || resolved.backend != fie::core::TskOpenBackend::PathBased) {
      return 1;
    }
  }

  // Explicitly validate helper warning-detail formatter contract.
  if (fie::domain::op::formatWarningDetail({"x", "y", "z"}) != "x || y || z") return 1;

  return 0;
}

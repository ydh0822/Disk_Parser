#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/utils/MetadataFactory.h"
#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"
#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"

#include <QDir>
#include <QFile>

class E2EFakeReader final : public fie::core::IImageReader {
public:
  bool open(const QString &imagePath, QString &error) override {
    Q_UNUSED(error)
    m_open = true;
    m_path = imagePath;
    return true;
  }
  void close() override { m_open = false; }
  QByteArray read(quint64, quint64, QString &error) override {
    Q_UNUSED(error)
    return {};
  }
  quint64 size() const override { return 0; }
  bool isOpen() const override { return m_open; }
  QString path() const override { return m_path; }

  bool m_open{true};
  QString m_path{"synthetic.e01"};
};

class E2EFailBridge final : public fie::core::ITskReaderBridge {
public:
  bool openFromReader(const std::shared_ptr<fie::core::IImageReader> &, TSK_IMG_INFO *&out, QString &error) override {
    out = nullptr;
    error = "Reader-backed open failed";
    return false;
  }
  void close(TSK_IMG_INFO *) override {}
  bool isImplemented() const override { return true; }
};

int runEndToEndSemanticsTests() {
  auto reader = std::make_shared<E2EFakeReader>();
  fie::core::TskImageHandleAdapter adapter(reader, std::make_unique<E2EFailBridge>(), false);
  QString error;
  if (adapter.open(error) || error != "Reader-backed open failed" || adapter.isPathFallbackEnabled() ||
      !adapter.lastWarning().isEmpty()) {
    return 1;
  }

  fie::domain::ImageInfo image;
  image.path = "fixture.E01";

  fie::domain::PartitionInfo partition;
  partition.identifier = "p2";

  fie::domain::ExtractionResult extraction;
  extraction.source.fullPath = "/dir/file.txt";
  extraction.source.name = "file.txt";
  extraction.source.sizeBytes = 10;
  extraction.source.inode = 42;
  extraction.source.isAllocated = false;
  extraction.source.isDeleted = true;
  extraction.source.metadata.timestamps.created = QDateTime::fromSecsSinceEpoch(1, Qt::UTC);

  fie::domain::NtfsMetadata ntfs;
  ntfs.standardInfo.modified = QDateTime::fromSecsSinceEpoch(2, Qt::UTC);
  ntfs.fileNameInfo.modified = QDateTime::fromSecsSinceEpoch(3, Qt::UTC);
  ntfs.adsNames = {"Zone.Identifier", "Secret"};
  extraction.source.metadata.ntfs = ntfs;

  extraction.destinationPath = "/out/file.txt";
  extraction.sha256 = "abc";
  extraction.primaryOutcome = "success";
  extraction.status = "success_with_warning";
  extraction.warning = "non-fatal warning";
  extraction.bytesWritten = 8;

  const auto rec = fie::utils::createCatalogRecord(image, partition, extraction);
  if (rec.sourceImagePath != "fixture.E01" || rec.partitionIdentifier != "p2" || rec.adsNames.size() != 2 ||
      rec.bytesWritten != 8 || rec.warning != "non-fatal warning") {
    return 1;
  }

  const QString basePath = QDir::currentPath() + "/.e2e-semantics";
  const QString jsonPath = basePath + ".json";
  const QString csvPath = basePath + ".csv";
  std::vector<fie::domain::CatalogRecord> rows{rec};

  if (!fie::utils::MetadataSerializerJson::write(jsonPath, rows, error)) {
    return 1;
  }
  if (!fie::utils::MetadataSerializerCsv::write(csvPath, rows, error)) {
    QFile::remove(jsonPath);
    return 1;
  }

  QFile json(jsonPath);
  if (!json.open(QIODevice::ReadOnly)) {
    QFile::remove(jsonPath);
    QFile::remove(csvPath);
    return 1;
  }
  const QByteArray jsonText = json.readAll();

  QFile csv(csvPath);
  if (!csv.open(QIODevice::ReadOnly)) {
    QFile::remove(jsonPath);
    QFile::remove(csvPath);
    return 1;
  }
  const QByteArray csvText = csv.readAll();

  QFile::remove(jsonPath);
  QFile::remove(csvPath);

  if (!jsonText.contains("ads_names") || !jsonText.contains("Zone.Identifier") ||
      !csvText.contains("ads_names") || !csvText.contains("Zone.Identifier;Secret")) {
    return 1;
  }

  return 0;
}

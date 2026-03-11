#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"
#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/utils/LogManager.h"

#include <QMainWindow>
#include <memory>

class QAction;
class QPlainTextEdit;
class QTableWidget;
class QTextEdit;
class QTreeWidget;
class QTreeWidgetItem;

namespace fie::gui {

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget *parent = nullptr);

private slots:
  void onOpenImage();
  void onPartitionSelected();
  void onFileSelected();
  void onExtractSelected();
  void onExportCatalog();

private:
  void setupUi();
  void setupMenu();
  void appendLog(const QString &line);
  void populatePartitions();
  void populateFiles(QTreeWidgetItem *selectedTreeItem);
  void setBusy(bool busy, const QString &message = {});

  std::shared_ptr<core::IImageReader> m_reader;
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  domain::ImageInfo m_imageInfo;
  std::vector<domain::PartitionInfo> m_partitions;
  std::vector<domain::FileEntry> m_files;
  std::vector<domain::CatalogRecord> m_catalog;
  int m_selectedPartitionIndex{-1};
  QString m_currentLogicalPath{"/"};

  utils::LogManager m_logManager;

  QTreeWidget *m_partitionTree{nullptr};
  QTableWidget *m_fileTable{nullptr};
  QTextEdit *m_metadataPanel{nullptr};
  QPlainTextEdit *m_logPanel{nullptr};
  QAction *m_stopAction{nullptr};
};

} // namespace fie::gui
